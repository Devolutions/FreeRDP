/**
 * NOW endpoint tests using the real asynchronous drdynvc worker and PDU path.
 * Licensed under the Apache License, Version 2.0.
 */

#include <stdio.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/interlocked.h>
#include <winpr/stream.h>
#include <winpr/synch.h>
#include <winpr/thread.h>

#include <freerdp/client.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/nowproto.h>
#include <freerdp/svc.h>

#include "../../../drdynvc/client/drdynvc_main.h"

#define OPEN_HANDLE 1
#define MAX_OFFERS 128
#define TIMEOUT 10000
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
	UINT status;
	size_t count;
	BOOL checkRaceStatus;
} RESULT;

typedef struct
{
	NowProtoEndpoint* endpoint;
	size_t received;
	size_t closed;
} OFFER;

typedef struct
{
	PCHANNEL_INIT_EVENT_EX_FN init;
	PCHANNEL_OPEN_EVENT_EX_FN event;
	drdynvcPlugin* plugin;
	NowProtoClientContext* legacy;
	DrdynvcDispatcher* dispatcher;
	OFFER offers[MAX_OFFERS];
	size_t count;
	volatile LONG failed;
	BOOL direct;
	BOOL synchronous;
	BOOL insideOffer;
	BOOL closeInOffer;
	BOOL closeInReceive;
	BOOL releaseInClosed;
	BOOL reenterCompletion;
	BOOL cancelReenter;
	BOOL closingSession;
	UINT optinStatus;
	RESULT callbackClose;
	RESULT reentrant;
	RESULT canceled;
	INT32 createStatus;
	UINT32 lastWrite;
	UINT32 lastClose;
	UINT32 writes;
	UINT32 closes;
	BYTE lastByte;
	UINT failCommand;
	HANDLE entered;
	HANDLE release;
	HANDLE flushed;
	DWORD workerId;
} TEST_NOW;

static TEST_NOW test;
static int initHandle;

static void fail(void)
{
	InterlockedCompareExchange(&test.failed, 1, 0);
}

static UINT VCAPITYPE init_ex(void* user, WINPR_ATTR_UNUSED void* context,
                              WINPR_ATTR_UNUSED void* handle,
                              WINPR_ATTR_UNUSED PCHANNEL_DEF channels, WINPR_ATTR_UNUSED INT count,
                              WINPR_ATTR_UNUSED ULONG version, PCHANNEL_INIT_EVENT_EX_FN init)
{
	test.plugin = user;
	test.init = init;
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE open_ex(WINPR_ATTR_UNUSED void* handle, LPDWORD openHandle,
                              WINPR_ATTR_UNUSED PCHAR name, PCHANNEL_OPEN_EVENT_EX_FN event)
{
	*openHandle = OPEN_HANDLE;
	test.event = event;
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE close_ex(WINPR_ATTR_UNUSED void* handle, WINPR_ATTR_UNUSED DWORD openHandle)
{
	return CHANNEL_RC_OK;
}

static UINT VCAPITYPE write_ex(WINPR_ATTR_UNUSED void* handle, DWORD openHandle, void* buffer,
                               ULONG length, void* user)
{
	const BYTE* data = buffer;
	if (data && length >= 2)
	{
		const BYTE command = data[0] >> 4;
		if (test.failCommand == command)
			return ERROR_WRITE_FAULT;
		if ((command == CREATE_REQUEST_PDU) && (length == 6))
			test.createStatus = (INT32)(data[2] | ((UINT32)data[3] << 8) | ((UINT32)data[4] << 16) |
			                            ((UINT32)data[5] << 24));
		else if (command == DATA_PDU)
		{
			test.lastWrite = data[1];
			test.lastByte = data[length - 1];
			test.writes++;
		}
		else if (command == CLOSE_REQUEST_PDU)
		{
			if (test.insideOffer)
				fail(); /* Close must run after OnOpen's native caller has returned. */
			test.lastClose = data[1];
			test.closes++;
		}
	}
	test.event(test.plugin, openHandle, CHANNEL_EVENT_WRITE_COMPLETE, user, 0, 0, 0);
	return CHANNEL_RC_OK;
}

static OFFER* offer_of(NowProtoEndpoint* endpoint)
{
	for (size_t x = 0; x < test.count; x++)
	{
		if (test.offers[x].endpoint == endpoint)
			return &test.offers[x];
	}
	fail();
	return nullptr;
}

static void completed(WINPR_ATTR_UNUSED void* custom, WINPR_ATTR_UNUSED NowProtoEndpoint* endpoint,
                      void* token, UINT status)
{
	if (GetCurrentThreadId() != test.workerId)
		fail();
	RESULT* result = token;
	if (result->checkRaceStatus && status != CHANNEL_RC_OK && status != ERROR_NOT_CONNECTED)
		fail();
	result->status = status;
	result->count++;
	if (test.cancelReenter && status == ERROR_OPERATION_ABORTED)
	{
		BOOL queued = TRUE;
		NowProtoEndpoint* other = test.offers[2].endpoint;
		if (other->RequestClose(other, nullptr, &queued) != ERROR_NOT_CONNECTED || queued)
			fail();
		test.cancelReenter = FALSE;
	}
	if (test.reenterCompletion)
	{
		test.reenterCompletion = FALSE;
		BOOL queued = FALSE;
		const BYTE byte = 0x66;
		if (endpoint->SubmitWrite(endpoint, &byte, 1, &test.reentrant, &queued) != CHANNEL_RC_OK ||
		    !queued || test.reentrant.count)
			fail();
	}
}

static void offered(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint)
{
	if ((test.count == MAX_OFFERS) || (GetCurrentThreadId() != test.workerId))
	{
		fail();
		return;
	}
	endpoint->Retain(endpoint);
	test.offers[test.count++].endpoint = endpoint;
	test.insideOffer = TRUE;
	if (test.closeInOffer)
	{
		BOOL queued = FALSE;
		if (endpoint->RequestClose(endpoint, &test.callbackClose, &queued) != CHANNEL_RC_OK ||
		    !queued || test.callbackClose.count)
			fail();
	}
	test.insideOffer = FALSE;
}

static void received(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint, const BYTE* data,
                     size_t size)
{
	OFFER* offer = offer_of(endpoint);
	if (!offer)
		return;
	offer->received++;
	if ((GetCurrentThreadId() != test.workerId) || (size != 1) || (data[0] != 0x42))
		fail();
	if (test.closeInReceive)
	{
		BOOL queued = FALSE;
		if (endpoint->RequestClose(endpoint, &test.callbackClose, &queued) != CHANNEL_RC_OK ||
		    !queued)
			fail();
	}
}

static void closed(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint)
{
	OFFER* offer = offer_of(endpoint);
	if (!offer)
		return;
	offer->closed++;
	BOOL queued = TRUE;
	const BYTE data = 1;
	if ((GetCurrentThreadId() != test.workerId) ||
	    endpoint->RequestClose(endpoint, nullptr, &queued) != CHANNEL_RC_OK || queued ||
	    endpoint->SubmitWrite(endpoint, &data, 1, nullptr, &queued) != ERROR_NOT_CONNECTED ||
	    queued)
		fail();
	if (test.releaseInClosed)
	{
		offer->endpoint = nullptr;
		endpoint->Release(endpoint);
	}
	if (test.closingSession)
	{
		NowProtoEndpoint* other = test.offers[2].endpoint;
		queued = TRUE;
		const UINT status = other->RequestClose(other, nullptr, &queued);
		if ((status != CHANNEL_RC_OK && status != ERROR_NOT_CONNECTED) || queued)
			fail();
	}
}

static UINT connected(WINPR_ATTR_UNUSED DrdynvcClientContext* context, const char* name,
                      void* iface)
{
	if (strcmp(name, NOWPROTO_DVC_CHANNEL_NAME) != 0)
		return CHANNEL_RC_OK;
	test.legacy = iface;
	test.workerId = GetCurrentThreadId();
	if (test.direct && !test.count)
	{
		const NowProtoClientCallbacksV2 callbacks = {
			sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_2,
			nullptr,           offered,
			received,          closed,
			completed
		};
		test.optinStatus = freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks);
	}
	return CHANNEL_RC_OK;
}

static UINT noop(WINPR_ATTR_UNUSED void* payload)
{
	return CHANNEL_RC_OK;
}

static void record(void* payload, UINT status)
{
	RESULT* result = payload;
	result->status = status;
	result->count++;
}

static void flushed(WINPR_ATTR_UNUSED void* payload, UINT status)
{
	if (status != CHANNEL_RC_OK)
		fail();
	SetEvent(test.flushed);
}

static BOOL flush(void)
{
	if (test.synchronous)
		return TRUE;
	ResetEvent(test.flushed);
	UINT status = ERROR_NOT_READY;
	for (size_t x = 0; (x < TIMEOUT) && (status == ERROR_NOT_READY); x++)
	{
		status = freerdp_drdynvc_dispatcher_post(test.dispatcher, noop, flushed, nullptr);
		if (status == ERROR_NOT_READY)
			Sleep(1);
	}
	return status == CHANNEL_RC_OK && WaitForSingleObject(test.flushed, TIMEOUT) == WAIT_OBJECT_0;
}

static void receive_pdu(const BYTE* pdu, UINT32 size)
{
	test.event(test.plugin, OPEN_HANDLE, CHANNEL_EVENT_DATA_RECEIVED, (void*)pdu, size, size,
	           CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
}

static BOOL create_channel(BYTE id)
{
	BYTE pdu[128] = { CREATE_REQUEST_PDU << 4, id };
	const size_t size = strlen(NOWPROTO_DVC_CHANNEL_NAME) + 1;
	memcpy(&pdu[2], NOWPROTO_DVC_CHANNEL_NAME, size);
	test.createStatus = -1;
	receive_pdu(pdu, (UINT32)(size + 2));
	/* A callback can append another command after the first barrier was posted. */
	return flush() && flush() && test.createStatus == 0;
}

static void remote_close(BYTE id)
{
	const BYTE pdu[] = { CLOSE_REQUEST_PDU << 4, id };
	receive_pdu(pdu, sizeof(pdu));
}

static void remote_data(BYTE id)
{
	const BYTE pdu[] = { DATA_PDU << 4, id, 0x42 };
	receive_pdu(pdu, sizeof(pdu));
}

static UINT block_worker(WINPR_ATTR_UNUSED void* payload)
{
	SetEvent(test.entered);
	if (WaitForSingleObject(test.release, TIMEOUT) != WAIT_OBJECT_0)
		fail();
	return CHANNEL_RC_OK;
}

static BOOL block(RESULT* result)
{
	ResetEvent(test.entered);
	ResetEvent(test.release);
	return freerdp_drdynvc_dispatcher_post(test.dispatcher, block_worker, record, result) ==
	           CHANNEL_RC_OK &&
	       WaitForSingleObject(test.entered, TIMEOUT) == WAIT_OBJECT_0;
}

static BOOL write_and_wait(NowProtoEndpoint* endpoint, BYTE byte, UINT expected, BYTE id)
{
	RESULT result = { 0 };
	BOOL queued = FALSE;
	if (endpoint->SubmitWrite(endpoint, &byte, 1, &result, &queued) != CHANNEL_RC_OK || !queued ||
	    !flush())
		return FALSE;
	return result.count == 1 && result.status == expected &&
	       (expected != CHANNEL_RC_OK || test.lastWrite == id);
}

static DWORD WINAPI disconnect_worker(WINPR_ATTR_UNUSED void* arg)
{
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_DISCONNECTED, nullptr, 0);
	return 0;
}

typedef struct
{
	NowProtoEndpoint* endpoint;
	HANDLE started;
	size_t accepted;
	RESULT result;
} PRODUCER;

static DWORD WINAPI producer_worker(void* arg)
{
	PRODUCER* producer = arg;
	const BYTE data = 0x43;
	for (size_t x = 0; x < 200; x++)
	{
		BOOL queued = FALSE;
		const UINT status = producer->endpoint->SubmitWrite(producer->endpoint, &data, 1,
		                                                    &producer->result, &queued);
		if (status == CHANNEL_RC_OK && queued)
			producer->accepted++;
		else if (status != ERROR_NOT_CONNECTED || queued)
			fail();
		if (x == 0)
			SetEvent(producer->started);
	}
	return 0;
}

static BOOL disconnected;

static int run_case(BOOL direct, BOOL synchronous)
{
	int result = -1;
	HANDLE disconnector = nullptr;
	BOOL initialized = FALSE;
	BOOL terminated = FALSE;
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpClientContext);
	memset(&test, 0, sizeof(test));
	disconnected = FALSE;
	test.direct = direct;
	test.synchronous = synchronous;
	test.entered = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	test.release = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	test.flushed = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	rdpContext* context = freerdp_client_context_new(&entry);
	CHECK(context && test.entered && test.release && test.flushed);

	const char* channels[] = { "nowproto" };
	CHECK(freerdp_settings_set_bool(context->settings, FreeRDP_SynchronousDynamicChannels,
	                                synchronous));
	CHECK(freerdp_client_add_dynamic_channel(context->settings, 1, channels));
	PVIRTUALCHANNELENTRYEX pluginEntry =
	    WINPR_FUNC_PTR_CAST(freerdp_channels_load_static_addin_entry(
	                            DRDYNVC_SVC_CHANNEL_NAME, nullptr, nullptr,
	                            FREERDP_ADDIN_CHANNEL_STATIC | FREERDP_ADDIN_CHANNEL_ENTRYEX),
	                        PVIRTUALCHANNELENTRYEX);
	CHECK(pluginEntry);
	CHANNEL_ENTRY_POINTS_FREERDP_EX points = WINPR_C_ARRAY_INIT;
	points.cbSize = sizeof(points);
	points.protocolVersion = VIRTUAL_CHANNEL_VERSION_WIN2000;
	points.pVirtualChannelInitEx = init_ex;
	points.pVirtualChannelOpenEx = open_ex;
	points.pVirtualChannelCloseEx = close_ex;
	points.pVirtualChannelWriteEx = write_ex;
	points.MagicNumber = FREERDP_CHANNEL_MAGIC_NUMBER;
	points.context = context;
	CHECK(pluginEntry((PCHANNEL_ENTRY_POINTS_EX)&points, &initHandle) && test.init);
	test.plugin->context->OnChannelConnected = connected;
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_INITIALIZED, nullptr, 0);
	initialized = TRUE;

	/* Exercise acquisition/startup with the live manager before plugin initialization. */
	const UINT acquired =
	    freerdp_drdynvc_dispatcher_acquire(test.plugin->channel_mgr, &test.dispatcher);
	RESULT startup = { 0 };
	if (synchronous)
		CHECK(acquired == ERROR_NOT_SUPPORTED && !test.dispatcher);
	else
	{
		CHECK(acquired == CHANNEL_RC_OK);
		CHECK(freerdp_drdynvc_dispatcher_post(test.dispatcher, noop, record, &startup) ==
		      ERROR_NOT_READY);
		CHECK(startup.count == 0);
	}
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_CONNECTED, nullptr, 0);
	CHECK(test.event && (synchronous || test.plugin->thread));
	CHECK(create_channel(5));
	CHECK(test.legacy);
	CHECK(test.legacy->Write(test.legacy, nullptr, -1) == ERROR_INVALID_PARAMETER);

	if (!direct || synchronous)
	{
		if (direct)
			CHECK(test.optinStatus == ERROR_NOT_SUPPORTED);
		CHECK(!create_channel(6));
		BYTE data = 0x43;
		CHECK(test.legacy->Write(test.legacy, &data, 1) == CHANNEL_RC_OK);
		CHECK(test.lastWrite == 5);
		remote_close(5);
		CHECK(flush());
		CHECK(test.legacy->Write(test.legacy, &data, 1) == ERROR_NOT_CONNECTED);
		CHECK(create_channel(6));
		CHECK(test.legacy->Write(test.legacy, &data, 1) == CHANNEL_RC_OK);
		CHECK(test.lastWrite == 6);
		result = 0;
		goto cleanup;
	}

	CHECK(test.optinStatus == CHANNEL_RC_OK && test.count == 1);
	NowProtoClientCallbacksV2 callbacks = { sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_2,
		                                    nullptr,           offered,
		                                    received,          closed,
		                                    completed };
	CHECK(freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks) == ERROR_INVALID_STATE);
	callbacks.OperationCompleted = nullptr;
	CHECK(freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks) ==
	      ERROR_INVALID_PARAMETER);
	BYTE data = 0x43;
	BOOL queued = TRUE;
	CHECK(test.legacy->Write(test.legacy, &data, 1) == ERROR_INVALID_STATE);
	NowProtoEndpoint* first = test.offers[0].endpoint;
	CHECK(first->SubmitWrite(first, nullptr, 1, nullptr, &queued) == ERROR_INVALID_PARAMETER);
	CHECK(!queued);
	CHECK(first->SubmitWrite(first, &data, 0, nullptr, &queued) == ERROR_INVALID_PARAMETER);
	CHECK(first->RequestClose(first, nullptr, nullptr) == ERROR_INVALID_PARAMETER);
	CHECK(create_channel(6));
	NowProtoEndpoint* second = test.offers[1].endpoint;
	CHECK(first != second);
	CHECK(write_and_wait(first, data, CHANNEL_RC_OK, 5));
	CHECK(write_and_wait(second, data, CHANNEL_RC_OK, 6));
	remote_data(5);
	remote_data(6);
	CHECK(flush());
	CHECK(test.offers[0].received == 1 && test.offers[1].received == 1);

	/* Deterministically order a remote close ahead of a queued endpoint write. */
	RESULT blocking = { 0 };
	RESULT remoteFirst = { 0 };
	CHECK(block(&blocking));
	remote_close(5);
	CHECK(first->SubmitWrite(first, &data, 1, &remoteFirst, &queued) == CHANNEL_RC_OK && queued);
	SetEvent(test.release);
	CHECK(flush());
	CHECK(remoteFirst.count == 1 && remoteFirst.status == ERROR_NOT_CONNECTED);
	CHECK(test.offers[0].closed == 1 && test.offers[1].closed == 0);
	CHECK(first->RequestClose(first, nullptr, &queued) == CHANNEL_RC_OK && !queued);
	CHECK(create_channel(5));
	CHECK(first->RequestClose(first, nullptr, &queued) == CHANNEL_RC_OK && !queued);
	CHECK(test.offers[2].endpoint != first);
	CHECK(write_and_wait(test.offers[2].endpoint, data, CHANNEL_RC_OK, 5));

	/* Native send errors are completions, not submission failures. */
	test.failCommand = DATA_PDU;
	CHECK(write_and_wait(second, data, ERROR_WRITE_FAULT, 6));
	CHECK(test.offers[1].closed == 0);
	test.failCommand = CLOSE_REQUEST_PDU;
	RESULT closeResult = { 0 };
	CHECK(second->RequestClose(second, &closeResult, &queued) == CHANNEL_RC_OK && queued);
	CHECK(flush());
	/* Base Close overwrites its send failure with OnClose's result. */
	CHECK(closeResult.count == 1 && closeResult.status == CHANNEL_RC_OK);
	CHECK(test.offers[1].closed == 1);
	CHECK(second->RequestClose(second, nullptr, &queued) == CHANNEL_RC_OK && !queued);
	test.failCommand = 0;

	test.closeInOffer = TRUE;
	test.releaseInClosed = TRUE;
	CHECK(create_channel(7));
	CHECK(test.callbackClose.count == 1 && test.offers[3].closed == 1);
	CHECK(!test.offers[3].endpoint);
	test.closeInOffer = FALSE;
	test.closeInReceive = TRUE;
	CHECK(create_channel(8));
	remote_data(8);
	CHECK(flush() && flush());
	CHECK(test.callbackClose.count == 2 && test.offers[4].closed == 1);
	CHECK(!test.offers[4].endpoint);
	test.closeInReceive = FALSE;
	test.releaseInClosed = FALSE;

	/* Copy before enqueue; no caller buffer is consulted during execution. */
	blocking = (RESULT){ 0 };
	RESULT copied = { 0 };
	CHECK(block(&blocking));
	data = 0x55;
	CHECK(test.offers[2].endpoint->SubmitWrite(test.offers[2].endpoint, &data, 1, &copied,
	                                           &queued) == CHANNEL_RC_OK &&
	      queued);
	data = 0x99;
	SetEvent(test.release);
	CHECK(flush() && copied.count == 1 && test.lastByte == 0x55);
	test.reenterCompletion = TRUE;
	CHECK(write_and_wait(test.offers[2].endpoint, data, CHANNEL_RC_OK, 5));
	CHECK(flush() && test.reentrant.count == 1 && test.reentrant.status == CHANNEL_RC_OK);

	/* Local close ahead of remote close; repeated close commands are idempotent. */
	for (size_t x = 0; x < 30; x++)
	{
		CHECK(create_channel(9));
		NowProtoEndpoint* endpoint = test.offers[test.count - 1].endpoint;
		RESULT one = { 0 }, two = { 0 }, write = { 0 };
		blocking = (RESULT){ 0 };
		CHECK(block(&blocking));
		CHECK(endpoint->RequestClose(endpoint, &one, &queued) == CHANNEL_RC_OK && queued);
		CHECK(endpoint->RequestClose(endpoint, &two, &queued) == CHANNEL_RC_OK && queued);
		CHECK(endpoint->SubmitWrite(endpoint, &data, 1, &write, &queued) == CHANNEL_RC_OK &&
		      queued);
		remote_close(9);
		SetEvent(test.release);
		CHECK(flush());
		CHECK(one.count == 1 && one.status == CHANNEL_RC_OK);
		CHECK(two.count == 1 && two.status == CHANNEL_RC_OK);
		CHECK(write.count == 1 && write.status == ERROR_NOT_CONNECTED);
		CHECK(test.offers[test.count - 1].closed == 1);
	}

	/* Real concurrent producer versus remote/local close, not just queued ordering. */
	for (size_t x = 0; x < 20; x++)
	{
		CHECK(create_channel(10));
		NowProtoEndpoint* endpoint = test.offers[test.count - 1].endpoint;
		PRODUCER producer = { 0 };
		producer.endpoint = endpoint;
		producer.result.checkRaceStatus = TRUE;
		producer.started = CreateEvent(nullptr, TRUE, FALSE, nullptr);
		CHECK(producer.started);
		HANDLE thread = CreateThread(nullptr, 0, producer_worker, &producer, 0, nullptr);
		if (!thread)
		{
			CloseHandle(producer.started);
			CHECK(thread);
		}
		const DWORD started = WaitForSingleObject(producer.started, TIMEOUT);
		RESULT local = { 0 };
		UINT status = CHANNEL_RC_OK;
		if (x % 2)
			status = endpoint->RequestClose(endpoint, &local, &queued);
		else
			remote_close(10);
		const DWORD joined = WaitForSingleObject(thread, TIMEOUT);
		CloseHandle(thread);
		CloseHandle(producer.started);
		CHECK(started == WAIT_OBJECT_0 && joined == WAIT_OBJECT_0 && status == CHANNEL_RC_OK);
		CHECK(flush() && test.offers[test.count - 1].closed == 1);
		CHECK(producer.result.count == producer.accepted);
	}

	/* Stop while an operation is in flight: later accepted work must cancel once. */
	blocking = (RESULT){ 0 };
	CHECK(block(&blocking));
	CHECK(test.offers[2].endpoint->SubmitWrite(test.offers[2].endpoint, &data, 1, &test.canceled,
	                                           &queued) == CHANNEL_RC_OK &&
	      queued);
	test.cancelReenter = TRUE;
	test.closingSession = TRUE;
	/* A connection incarnation can end in the middle of static-channel assembly. */
	const BYTE fragment = DATA_PDU << 4;
	test.event(test.plugin, OPEN_HANDLE, CHANNEL_EVENT_DATA_RECEIVED, (void*)&fragment, 1, 3,
	           CHANNEL_FLAG_FIRST);
	disconnector = CreateThread(nullptr, 0, disconnect_worker, nullptr, 0, nullptr);
	CHECK(disconnector);
	RESULT rejected = { 0 };
	size_t accepted = 0;
	UINT admission = CHANNEL_RC_OK;
	for (size_t x = 0; x < TIMEOUT && admission == CHANNEL_RC_OK; x++)
	{
		admission = freerdp_drdynvc_dispatcher_post(test.dispatcher, noop, record, &rejected);
		if (admission == CHANNEL_RC_OK)
		{
			accepted++;
			Sleep(1);
		}
	}
	CHECK(admission == ERROR_NOT_CONNECTED);
	SetEvent(test.release);
	CHECK(WaitForSingleObject(disconnector, TIMEOUT) == WAIT_OBJECT_0);
	CloseHandle(disconnector);
	disconnector = nullptr;
	disconnected = TRUE;
	CHECK(blocking.count == 1 && blocking.status == CHANNEL_RC_OK);
	CHECK(test.canceled.count == 1 && test.canceled.status == ERROR_OPERATION_ABORTED);
	CHECK(!test.plugin->data_in && !test.plugin->firstFlagReceived && !test.plugin->totalLength);
	CHECK(!test.cancelReenter);
	CHECK(rejected.count == accepted);
	CHECK(!accepted || rejected.status == ERROR_OPERATION_ABORTED);
	CHECK(freerdp_drdynvc_dispatcher_post(test.dispatcher, noop, record, &startup) ==
	      ERROR_NOT_CONNECTED);
	CHECK(startup.count == 0);
	CHECK(first->RequestClose(first, nullptr, &queued) == CHANNEL_RC_OK && !queued);

	/* The same native manager reconnects, but old capabilities remain terminal. */
	DrdynvcDispatcher* old = test.dispatcher;
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_CONNECTED, nullptr, 0);
	disconnected = FALSE;
	test.dispatcher = test.plugin->dispatcher;
	CHECK(test.dispatcher && test.dispatcher != old);
	freerdp_drdynvc_dispatcher_retain(test.dispatcher);
	CHECK(flush());
	CHECK(freerdp_drdynvc_dispatcher_post(old, noop, record, &startup) == ERROR_NOT_CONNECTED);
	freerdp_drdynvc_dispatcher_release(old);
	/* Reconnect uses legacy until the newly-created NOW context explicitly opts in. */
	test.direct = FALSE;
	CHECK(create_channel(5));
	CHECK(test.legacy->Write(test.legacy, &data, 1) == CHANNEL_RC_OK && test.lastWrite == 5);
	const UINT32 beforeStaleClose = test.closes;
	CHECK(first->RequestClose(first, nullptr, &queued) == CHANNEL_RC_OK && !queued);
	CHECK(flush() && test.closes == beforeStaleClose);

	/* Terminated without Disconnected must still stop/join before freeing plugins. */
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_TERMINATED, nullptr, 0);
	terminated = TRUE;
	CHECK(freerdp_drdynvc_dispatcher_post(test.dispatcher, noop, record, &startup) ==
	      ERROR_NOT_CONNECTED);
	result = 0;

cleanup:
	if (test.release)
		SetEvent(test.release);
	if (disconnector)
	{
		WaitForSingleObject(disconnector, TIMEOUT);
		CloseHandle(disconnector);
		disconnected = TRUE;
	}
	if (initialized && !terminated)
	{
		if (!disconnected)
			test.init(test.plugin, &initHandle, CHANNEL_EVENT_DISCONNECTED, nullptr, 0);
		test.init(test.plugin, &initHandle, CHANNEL_EVENT_TERMINATED, nullptr, 0);
	}
	for (size_t x = 0; x < test.count; x++)
	{
		NowProtoEndpoint* endpoint = test.offers[x].endpoint;
		if (test.offers[x].closed != 1)
			result = -1;
		if (endpoint)
		{
			BOOL queued = TRUE;
			const BYTE byte = 1;
			if (endpoint->RequestClose(endpoint, nullptr, &queued) != CHANNEL_RC_OK || queued ||
			    endpoint->SubmitWrite(endpoint, &byte, 1, nullptr, &queued) !=
			        ERROR_NOT_CONNECTED ||
			    queued)
				result = -1;
			endpoint->Release(endpoint);
		}
	}
	freerdp_drdynvc_dispatcher_release(test.dispatcher);
	if (test.failed)
		result = -1;
	freerdp_client_context_free(context);
	CloseHandle(test.entered);
	CloseHandle(test.release);
	CloseHandle(test.flushed);
	return result;
}

int TestNowProtoLifetime(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);
	if (sizeof(NowProtoClientContext) != 4 * sizeof(void*))
		return -1;
	if (run_case(FALSE, FALSE) != 0 || run_case(TRUE, TRUE) != 0)
		return -1;
	return run_case(TRUE, FALSE);
}
