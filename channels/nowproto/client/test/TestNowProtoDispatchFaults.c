/**
 * Compile the production dispatcher/NOW implementation with local fault shims.
 * No production test hooks or symbol interposition into the shared library.
 * Licensed under the Apache License, Version 2.0.
 */

#include <freerdp/config.h>
#include <stdlib.h>
#include <stdio.h>
#include <winpr/crt.h>
#include <winpr/collections.h>
#include <winpr/interlocked.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <freerdp/client.h>
#include <freerdp/client/drdynvc.h>
#include <freerdp/client/nowproto.h>

static BOOL failAlloc;
static BOOL failMalloc;
static BOOL failPost;
static BOOL failThread;
static BOOL failWait;
static BOOL failPeek;
static HANDLE failSignal;
static HANDLE failJoin;
static BOOL emptyJoinError;

static void* fault_calloc(size_t count, size_t size)
{
	if (failAlloc)
	{
		failAlloc = FALSE;
		return nullptr;
	}
	return calloc(count, size);
}

static void* fault_malloc(size_t size)
{
	if (failMalloc)
	{
		failMalloc = FALSE;
		return nullptr;
	}
	return malloc(size);
}

static BOOL fault_post(wMessageQueue* queue, void* context, UINT32 type, void* wParam, void* lParam)
{
	if (failPost)
	{
		failPost = FALSE;
		return FALSE;
	}
	return MessageQueue_Post(queue, context, type, wParam, lParam);
}

static HANDLE fault_thread(LPSECURITY_ATTRIBUTES attributes, size_t stack,
                           LPTHREAD_START_ROUTINE start, void* arg, DWORD flags, LPDWORD id)
{
	if (failThread)
	{
		failThread = FALSE;
		return nullptr;
	}
	return CreateThread(attributes, stack, start, arg, flags, id);
}

static DWORD fault_wait(DWORD count, const HANDLE* events, BOOL all, DWORD timeout)
{
	if (failWait)
	{
		failWait = FALSE;
		return WAIT_FAILED;
	}
	return WaitForMultipleObjects(count, events, all, timeout);
}

static int fault_peek(wMessageQueue* queue, wMessage* message, BOOL remove)
{
	const int result = MessageQueue_Peek(queue, message, remove);
	if (failPeek && result > 0)
	{
		failPeek = FALSE;
		return -1; /* Model ResetEvent failing after removal, not before. */
	}
	return result;
}

static BOOL fault_signal(HANDLE event)
{
	if (event == failSignal)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	return SetEvent(event);
}

static DWORD fault_join(HANDLE handle, DWORD timeout)
{
	if (handle == failJoin)
	{
		SetLastError(emptyJoinError ? ERROR_SUCCESS : ERROR_INVALID_HANDLE);
		return WAIT_FAILED;
	}
	return WaitForSingleObject(handle, timeout);
}

#define calloc fault_calloc
#define malloc fault_malloc
#define MessageQueue_Post fault_post
#define MessageQueue_Peek fault_peek
#define CreateThread fault_thread
#define WaitForMultipleObjects fault_wait
#define WaitForSingleObject fault_join
#define SetEvent fault_signal
#define freerdp_drdynvc_dispatcher_acquire local_dispatcher_acquire
#define freerdp_drdynvc_dispatcher_retain local_dispatcher_retain
#define freerdp_drdynvc_dispatcher_release local_dispatcher_release
#define freerdp_drdynvc_dispatcher_post local_dispatcher_post
#define drdynvc_VirtualChannelEntryEx local_drdynvc_entry
#include "../../../drdynvc/client/drdynvc_main.c"
#undef TAG
#define freerdp_nowproto_client_set_callbacks local_nowproto_callbacks
#define nowproto_DVCPluginEntry local_nowproto_entry
#include "../nowproto_main.c"
#undef calloc
#undef malloc
#undef MessageQueue_Post
#undef MessageQueue_Peek
#undef CreateThread
#undef WaitForMultipleObjects
#undef WaitForSingleObject
#undef SetEvent

#define CHECK(condition)                                                    \
	do                                                                      \
	{                                                                       \
		if (!(condition))                                                   \
		{                                                                   \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
			goto cleanup;                                                   \
		}                                                                   \
	} while (0)

typedef struct
{
	size_t ran;
	size_t completed;
	UINT status;
	HANDLE done;
	HANDLE entered;
	HANDLE release;
} PAYLOAD;

static UINT run(void* arg)
{
	PAYLOAD* payload = arg;
	payload->ran++;
	if (payload->entered)
	{
		SetEvent(payload->entered);
		if (WaitForSingleObject(payload->release, 10000) != WAIT_OBJECT_0)
			return ERROR_TIMEOUT;
	}
	return CHANNEL_RC_OK;
}

static void complete(void* arg, UINT status)
{
	PAYLOAD* payload = arg;
	payload->status = status;
	payload->completed++;
	if (payload->done)
		SetEvent(payload->done);
}

static UINT VCAPITYPE open_ex(WINPR_ATTR_UNUSED void* handle, LPDWORD openHandle,
                              WINPR_ATTR_UNUSED PCHAR name,
                              WINPR_ATTR_UNUSED PCHANNEL_OPEN_EVENT_EX_FN event)
{
	*openHandle = 1;
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE close_ex(WINPR_ATTR_UNUSED void* handle, WINPR_ATTR_UNUSED DWORD openHandle)
{
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE unknown_write(void* handle, WINPR_ATTR_UNUSED DWORD openHandle, void* data,
                                    ULONG size, void* user)
{
	PAYLOAD* response = handle;
	const BYTE* bytes = data;
	const BOOL create = size == 6 && (bytes[0] >> 4) == CREATE_REQUEST_PDU;
	if (create)
	{
		response->completed++;
		response->status = bytes[2] | ((UINT32)bytes[3] << 8) | ((UINT32)bytes[4] << 16) |
		                   ((UINT32)bytes[5] << 24);
	}
	Stream_Release(user); /* In-process static-channel WRITE_COMPLETE. */
	if (create)
		SetEvent(response->done);
	return CHANNEL_RC_OK;
}

static BOOL start(drdynvcPlugin* plugin)
{
	return drdynvc_virtual_channel_event_connected(plugin, nullptr, 0) == CHANNEL_RC_OK;
}

static int scenario(size_t which)
{
	int result = -1;
	rdpContext* context = nullptr;
	drdynvcPlugin* plugin = calloc(1, sizeof(*plugin));
	DrdynvcDispatcher* dispatcher = nullptr;
	PAYLOAD blocking = { 0 }, pending = { 0 }, rejected = { 0 };
	blocking.entered = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	blocking.release = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	pending.done = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	CHECK(plugin && blocking.entered && blocking.release && pending.done);
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpClientContext);
	context = freerdp_client_context_new(&entry);
	CHECK(context);
	plugin->rdpcontext = context;
	plugin->log = WLog_Get("test.dispatcher");
	plugin->async = TRUE;
	plugin->channelEntryPoints.pVirtualChannelOpenEx = open_ex;
	plugin->channelEntryPoints.pVirtualChannelCloseEx = close_ex;
	CHECK(drdynvc_virtual_channel_event_initialized(plugin, nullptr, 0) == CHANNEL_RC_OK);

	if (which == 7)
	{
		/* No acquisition: exercise the unchanged default async PDU/QUIT path. */
		plugin->InitHandle = &pending;
		plugin->channelEntryPoints.pVirtualChannelWriteEx = unknown_write;
		CHECK(start(plugin) && !plugin->dispatcher);
		const BYTE request[] = { CREATE_REQUEST_PDU << 4, 77, 'm', 'i', 's', 's', 0 };
		CHECK(drdynvc_virtual_channel_event_data_received(
		          plugin, (void*)request, sizeof(request), sizeof(request),
		          CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST) == CHANNEL_RC_OK);
		CHECK(WaitForSingleObject(pending.done, 10000) == WAIT_OBJECT_0);
		CHECK(pending.completed == 1 && pending.status != CHANNEL_RC_OK);
		CHECK(drdynvc_virtual_channel_event_disconnected(plugin) == CHANNEL_RC_OK);
		CHECK(!plugin->thread && !plugin->dispatcher);
		CHECK(drdynvc_virtual_channel_event_terminated(plugin) == CHANNEL_RC_OK);
		plugin = nullptr;
		result = 0;
		goto cleanup;
	}

	failAlloc = TRUE;
	CHECK(local_dispatcher_acquire(plugin->channel_mgr, &dispatcher) == ERROR_NOT_ENOUGH_MEMORY);
	CHECK(!dispatcher && !plugin->dispatcher);
	CHECK(local_dispatcher_acquire(plugin->channel_mgr, &dispatcher) == CHANNEL_RC_OK);
	CHECK(local_dispatcher_post(dispatcher, run, complete, &rejected) == ERROR_NOT_READY);
	CHECK(!rejected.ran && !rejected.completed);

	if (which == 0)
	{
		failThread = TRUE;
		CHECK(!start(plugin));
		CHECK(!plugin->thread);
		CHECK(local_dispatcher_post(dispatcher, run, complete, &rejected) == ERROR_NOT_CONNECTED);
		CHECK(drdynvc_virtual_channel_event_terminated(plugin) == CHANNEL_RC_OK);
		plugin = nullptr;
		CHECK(!rejected.completed);
		result = 0;
		goto cleanup;
	}
	if (which == 1)
	{
		/* Partial startup termination, even before a static channel was opened. */
		CHECK(drdynvc_virtual_channel_event_terminated(plugin) == CHANNEL_RC_OK);
		plugin = nullptr;
		CHECK(local_dispatcher_post(dispatcher, run, complete, &rejected) == ERROR_NOT_CONNECTED);
		result = 0;
		goto cleanup;
	}

	CHECK(start(plugin));
	/* A task published before worker startup is rejected; wait for its ready state. */
	for (size_t x = 0; x < 10000 && !drdynvc_dispatcher_running(dispatcher); x++)
		Sleep(1);
	CHECK(drdynvc_dispatcher_running(dispatcher));
	CHECK(local_dispatcher_post(dispatcher, run, complete, &blocking) == CHANNEL_RC_OK);
	CHECK(WaitForSingleObject(blocking.entered, 10000) == WAIT_OBJECT_0);

	failAlloc = TRUE;
	CHECK(local_dispatcher_post(dispatcher, run, complete, &rejected) == ERROR_NOT_ENOUGH_MEMORY);
	failPost = TRUE;
	CHECK(local_dispatcher_post(dispatcher, run, complete, &rejected) == ERROR_INTERNAL_ERROR);
	CHECK(!rejected.ran && !rejected.completed);

	DVCMAN* manager = (DVCMAN*)plugin->channel_mgr;
	const size_t streams = StreamPool_UsedCount(manager->pool);
	const BYTE pdu[] = { DATA_PDU << 4, 99, 1 };
	failPost = TRUE;
	CHECK(drdynvc_virtual_channel_event_data_received(plugin, (void*)pdu, sizeof(pdu), sizeof(pdu),
	                                                  CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST) ==
	      ERROR_INTERNAL_ERROR);
	CHECK(!plugin->data_in && StreamPool_UsedCount(manager->pool) == streams);

	NOWPROTO_PLUGIN now = { 0 };
	CHECK(InitializeCriticalSectionEx(&now.lock, 0, 0));
	BOOL accept = TRUE;
	IWTSVirtualChannelCallback* channelCallback = nullptr;
	failAlloc = TRUE;
	const UINT offered =
	    nowproto_on_new_channel(&now.listenerCallback, nullptr, nullptr, &accept, &channelCallback);
	DeleteCriticalSection(&now.lock);
	CHECK(offered == CHANNEL_RC_NO_MEMORY && !accept && !channelCallback);

	NOWPROTO_CHANNEL endpoint = { 0 };
	endpoint.refs = 1;
	endpoint.dispatcher = dispatcher;
	BOOL queued = TRUE;
	const BYTE data = 1;
	failMalloc = TRUE;
	CHECK(nowproto_endpoint_write(&endpoint.endpoint, &data, 1, nullptr, &queued) ==
	      ERROR_NOT_ENOUGH_MEMORY);
	CHECK(!queued && endpoint.refs == 1);
	failPost = TRUE;
	CHECK(nowproto_endpoint_write(&endpoint.endpoint, &data, 1, nullptr, &queued) ==
	      ERROR_INTERNAL_ERROR);
	CHECK(!queued && endpoint.refs == 1);

	CHECK(local_dispatcher_post(dispatcher, run, complete, &pending) == CHANNEL_RC_OK);
	if (which == 2)
		failWait = TRUE;
	else if (which == 3)
		failPeek = TRUE;
	else if (which == 4)
	{
		/* Stop/wake failure must not join, free or terminate the live worker. */
		failSignal = dispatcher->stop;
		CHECK(drdynvc_virtual_channel_event_disconnected(plugin) == ERROR_INTERNAL_ERROR);
		CHECK(plugin->thread && plugin->channel_mgr && plugin->queue);
		failSignal = nullptr;
	}
	else
	{
		failJoin = plugin->thread;
		emptyJoinError = which == 6;
		CHECK(drdynvc_virtual_channel_event_disconnected(plugin) ==
		      (emptyJoinError ? ERROR_INTERNAL_ERROR : ERROR_INVALID_HANDLE));
		CHECK(plugin->thread && plugin->channel_mgr && plugin->queue);
		failJoin = nullptr;
	}
	SetEvent(blocking.release);
	CHECK(WaitForSingleObject(pending.done, 10000) == WAIT_OBJECT_0);
	CHECK(pending.completed == 1 && !pending.ran && pending.status == ERROR_OPERATION_ABORTED);
	CHECK(local_dispatcher_post(dispatcher, run, complete, &rejected) == ERROR_NOT_CONNECTED);
	CHECK(drdynvc_virtual_channel_event_terminated(plugin) == CHANNEL_RC_OK);
	plugin = nullptr;
	CHECK(blocking.completed == 1 && blocking.ran == 1 && blocking.status == CHANNEL_RC_OK);
	CHECK(local_dispatcher_post(dispatcher, run, complete, &rejected) == ERROR_NOT_CONNECTED);
	CHECK(!rejected.completed);
	result = 0;

cleanup:
	failAlloc = failMalloc = failPost = failThread = failWait = failPeek = FALSE;
	failSignal = failJoin = nullptr;
	emptyJoinError = FALSE;
	if (blocking.release)
		SetEvent(blocking.release);
	if (plugin)
	{
		if (plugin->dispatcher)
			(void)drdynvc_dispatcher_stop(plugin->dispatcher);
		if (plugin->thread)
		{
			WaitForSingleObject(plugin->thread, 10000);
			CloseHandle(plugin->thread);
		}
		if (plugin->channel_mgr)
			dvcman_free(plugin, plugin->channel_mgr);
		MessageQueue_Free(plugin->queue);
		local_dispatcher_release(plugin->dispatcher);
		free(plugin);
	}
	local_dispatcher_release(dispatcher);
	freerdp_client_context_free(context);
	CloseHandle(blocking.entered);
	CloseHandle(blocking.release);
	CloseHandle(pending.done);
	return result;
}

int TestNowProtoDispatchFaults(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);
	for (size_t which = 0; which < 8; which++)
	{
		if (scenario(which) != 0)
			return -1;
	}
	return 0;
}
