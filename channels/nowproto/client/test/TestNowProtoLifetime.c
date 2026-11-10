/**
 * NOW endpoint lifetime tests with the real async drdynvc PDU worker.
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
#define BARRIER_ID 250
#define MAX_OFFERS 256
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
	IWTSListenerCallback barrierListener;
	IWTSVirtualChannelCallback barrierCallback;
	OFFER offers[MAX_OFFERS];
	size_t count;
	CRITICAL_SECTION lock;
	volatile LONG failed;
	volatile LONG blockWrite;
	BOOL direct;
	BOOL registered;
	BOOL retireInOffer;
	BOOL retireInReceive;
	BOOL releaseInClosed;
	BOOL blockReceive;
	BOOL nativeFreed;
	INT32 createStatus;
	UINT32 lastWrite;
	UINT32 lastClose;
	UINT32 writes;
	UINT32 closes;
	size_t remainingWrite;
	UINT failCommand;
	HANDLE writeEntered;
	HANDLE writeRelease;
	HANDLE receiveEntered;
	HANDLE receiveRelease;
	HANDLE barrier;
	DWORD callbackThread;
} TEST_NOW;

static TEST_NOW test;
static int initHandle;

static void fail(void)
{
	(void)InterlockedCompareExchange(&test.failed, 1, 0);
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

static UINT32 pdu_id(const BYTE* data)
{
	const size_t length = (data[0] & 3) == 0 ? 1 : ((data[0] & 3) == 1 ? 2 : 4);
	UINT32 id = 0;
	for (size_t x = 0; x < length; x++)
		id |= (UINT32)data[1 + x] << (8 * x);
	return id;
}

static UINT VCAPITYPE write_ex(WINPR_ATTR_UNUSED void* handle, DWORD openHandle, void* buffer,
                               ULONG length, void* user)
{
	const BYTE* data = buffer;
	BOOL block = FALSE;
	UINT status = CHANNEL_RC_OK;
	EnterCriticalSection(&test.lock);
	if (test.nativeFreed)
		fail();
	if (data && length >= 2)
	{
		const BYTE command = data[0] >> 4;
		const UINT32 id = pdu_id(data);
		if (test.failCommand == command)
			status = ERROR_WRITE_FAULT;
		else if ((command == CREATE_REQUEST_PDU) && (length == 6) && id != BARRIER_ID)
			test.createStatus = (INT32)(data[2] | ((UINT32)data[3] << 8) | ((UINT32)data[4] << 16) |
			                            ((UINT32)data[5] << 24));
		else if ((command == DATA_PDU || command == DATA_FIRST_PDU) && id != BARRIER_ID)
		{
			test.lastWrite = id;
			test.writes++;
			if (test.remainingWrite)
			{
				const size_t idBytes = (data[0] & 3) == 0 ? 1 : ((data[0] & 3) == 1 ? 2 : 4);
				const size_t lengthCode = (data[0] >> 2) & 3;
				const size_t lengthBytes = lengthCode == 0 ? 1 : (lengthCode == 1 ? 2 : 4);
				const size_t header = 1 + idBytes + (command == DATA_FIRST_PDU ? lengthBytes : 0);
				const size_t payload = length - header;
				if (payload > test.remainingWrite)
					fail();
				else
					test.remainingWrite -= payload;
			}
			block = InterlockedCompareExchange(&test.blockWrite, 0, 1) == 1;
		}
		else if (command == CLOSE_REQUEST_PDU && id != BARRIER_ID)
		{
			if (test.remainingWrite)
				fail(); /* CLOSE must not interleave with a fragmented nonempty Write. */
			test.lastClose = id;
			test.closes++;
		}
	}
	LeaveCriticalSection(&test.lock);
	if (status != CHANNEL_RC_OK)
		return status;
	if (block)
	{
		SetEvent(test.writeEntered);
		if (WaitForSingleObject(test.writeRelease, TIMEOUT) != WAIT_OBJECT_0)
			fail();
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

static void offered(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint)
{
	if (test.count == MAX_OFFERS || test.nativeFreed || GetCurrentThreadId() != test.callbackThread)
	{
		fail();
		return;
	}
	endpoint->Retain(endpoint);
	test.offers[test.count++].endpoint = endpoint;
	if (test.retireInOffer && endpoint->Retire(endpoint) != CHANNEL_RC_OK)
		fail();
}

static void received(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint, const BYTE* data,
                     size_t size)
{
	OFFER* offer = offer_of(endpoint);
	if (!offer)
		return;
	if (test.nativeFreed || GetCurrentThreadId() != test.callbackThread || size != 1 ||
	    data[0] != 0x42)
		fail();
	offer->received++;
	if (test.blockReceive)
	{
		SetEvent(test.receiveEntered);
		if (WaitForSingleObject(test.receiveRelease, TIMEOUT) != WAIT_OBJECT_0)
			fail();
	}
	if (test.retireInReceive && endpoint->Retire(endpoint) != CHANNEL_RC_OK)
		fail();
}

static void closed(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint)
{
	OFFER* offer = offer_of(endpoint);
	if (!offer)
		return;
	offer->closed++;
	const BYTE data = 1;
	if (test.nativeFreed || endpoint->Retire(endpoint) != CHANNEL_RC_OK ||
	    endpoint->Write(endpoint, &data, 1) != ERROR_NOT_CONNECTED)
		fail(); /* A rejected write touches no transport, even inside Closed. */
	if (test.releaseInClosed)
	{
		offer->endpoint = nullptr;
		endpoint->Release(endpoint);
	}
}

static UINT connected(WINPR_ATTR_UNUSED DrdynvcClientContext* context, const char* name,
                      void* iface)
{
	if (strcmp(name, NOWPROTO_DVC_CHANNEL_NAME) != 0)
		return CHANNEL_RC_OK;
	test.legacy = iface;
	test.callbackThread = GetCurrentThreadId();
	if (test.direct && !test.registered)
	{
		const NowProtoClientCallbacksV3 callbacks = {
			sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_3,
			nullptr,           offered,
			received,          closed
		};
		const UINT status = freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks);
		test.registered = status == CHANNEL_RC_OK;
		return status;
	}
	return CHANNEL_RC_OK;
}

static UINT barrier_open(WINPR_ATTR_UNUSED IWTSVirtualChannelCallback* callback)
{
	EnterCriticalSection(&test.lock);
	SetEvent(test.barrier);
	LeaveCriticalSection(&test.lock);
	return CHANNEL_RC_OK;
}

static UINT barrier_data(WINPR_ATTR_UNUSED IWTSVirtualChannelCallback* callback,
                         WINPR_ATTR_UNUSED wStream* data)
{
	return barrier_open(callback);
}

static UINT barrier_close(WINPR_ATTR_UNUSED IWTSVirtualChannelCallback* callback)
{
	return CHANNEL_RC_OK;
}

static UINT barrier_new(WINPR_ATTR_UNUSED IWTSListenerCallback* callback,
                        WINPR_ATTR_UNUSED IWTSVirtualChannel* channel, WINPR_ATTR_UNUSED BYTE* data,
                        BOOL* accept, IWTSVirtualChannelCallback** result)
{
	*accept = TRUE;
	*result = &test.barrierCallback;
	return CHANNEL_RC_OK;
}

static BOOL install_barrier(void)
{
	test.barrierListener.OnNewChannelConnection = barrier_new;
	test.barrierCallback.OnOpen = barrier_open;
	test.barrierCallback.OnDataReceived = barrier_data;
	test.barrierCallback.OnClose = barrier_close;
	IWTSVirtualChannelManager* manager = test.plugin->channel_mgr;
	IWTSListener* listener = nullptr;
	return manager->CreateListener(manager, "now-test-barrier", 0, &test.barrierListener,
	                               &listener) == CHANNEL_RC_OK;
}

static void receive_pdu(const BYTE* pdu, UINT32 size)
{
	test.event(test.plugin, OPEN_HANDLE, CHANNEL_EVENT_DATA_RECEIVED, (void*)pdu, size, size,
	           CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST);
}

static void create_pdu(BYTE id, const char* name)
{
	BYTE pdu[128] = { CREATE_REQUEST_PDU << 4, id };
	const size_t size = strlen(name) + 1;
	memcpy(&pdu[2], name, size);
	receive_pdu(pdu, (UINT32)(size + 2));
}

static BOOL open_barrier(void)
{
	ResetEvent(test.barrier);
	create_pdu(BARRIER_ID, "now-test-barrier");
	if (WaitForSingleObject(test.barrier, TIMEOUT) != WAIT_OBJECT_0)
		return FALSE;
	/* WinPR's pipe-backed events do not establish TSan-visible memory ordering. */
	EnterCriticalSection(&test.lock);
	LeaveCriticalSection(&test.lock);
	return TRUE;
}

static BOOL flush(void)
{
	const BYTE pdu[] = { DATA_PDU << 4, BARRIER_ID, 0 };
	ResetEvent(test.barrier);
	receive_pdu(pdu, sizeof(pdu));
	if (WaitForSingleObject(test.barrier, TIMEOUT) != WAIT_OBJECT_0)
		return FALSE;
	EnterCriticalSection(&test.lock);
	LeaveCriticalSection(&test.lock);
	return TRUE;
}

static BOOL create_channel(BYTE id)
{
	test.createStatus = -1;
	create_pdu(id, NOWPROTO_DVC_CHANNEL_NAME);
	return flush() && test.createStatus == 0;
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

typedef struct
{
	NowProtoEndpoint* endpoint;
	UINT status;
	HANDLE started;
	HANDLE finished;
	BOOL retire;
	const BYTE* bytes;
	UINT32 size;
} OPERATION;

static DWORD WINAPI operation(void* arg)
{
	OPERATION* op = arg;
	const BYTE byte = 0x43;
	SetEvent(op->started);
	op->status = op->retire ? op->endpoint->Retire(op->endpoint)
	                        : op->endpoint->Write(op->endpoint, op->bytes ? op->bytes : &byte,
	                                              op->bytes ? op->size : 1);
	SetEvent(op->finished);
	return 0;
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
	size_t successes;
} PRODUCER;

static DWORD WINAPI producer_worker(void* arg)
{
	PRODUCER* producer = arg;
	const BYTE data = 0x43;
	for (size_t x = 0; x < 200; x++)
	{
		const UINT status = producer->endpoint->Write(producer->endpoint, &data, 1);
		if (status == CHANNEL_RC_OK)
			producer->successes++;
		else if (status != ERROR_NOT_CONNECTED)
			fail();
		if (x == 0)
			SetEvent(producer->started);
	}
	return 0;
}

static int run_case(BOOL direct, BOOL synchronous)
{
	int result = -1;
	BOOL initialized = FALSE;
	BOOL disconnected = FALSE;
	HANDLE writer = nullptr;
	HANDLE retirer = nullptr;
	HANDLE disconnector = nullptr;
	OPERATION write = { 0 }, retire = { 0 };
	BYTE fragmented[5000] = { 0 };
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpClientContext);
	memset(&test, 0, sizeof(test));
	if (!InitializeCriticalSectionEx(&test.lock, 0, 0))
		return -1;
	test.direct = direct;
	test.writeEntered = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	test.writeRelease = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	test.receiveEntered = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	test.receiveRelease = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	test.barrier = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	write.started = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	write.finished = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	retire.started = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	retire.finished = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	retire.retire = TRUE;
	rdpContext* context = freerdp_client_context_new(&entry);
	CHECK(context && test.writeEntered && test.writeRelease && test.receiveEntered &&
	      test.receiveRelease && test.barrier && write.started && write.finished &&
	      retire.started && retire.finished);
	const char* channels[] = { "nowproto" };
	/* Async cases use the actual default, not an explicit FALSE override. */
	CHECK(!freerdp_settings_get_bool(context->settings, FreeRDP_SynchronousDynamicChannels));
	if (synchronous)
		CHECK(
		    freerdp_settings_set_bool(context->settings, FreeRDP_SynchronousDynamicChannels, TRUE));
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
	CHECK(install_barrier());
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_CONNECTED, nullptr, 0);
	CHECK(test.event && (synchronous ? !test.plugin->thread : !!test.plugin->thread));
	CHECK(open_barrier() && create_channel(5));
	CHECK(synchronous || test.callbackThread != GetCurrentThreadId());
	CHECK(test.legacy);
	CHECK(test.legacy->Write(test.legacy, nullptr, -1) == ERROR_INVALID_PARAMETER);
	BYTE data = 0x43;
	CHECK(test.legacy->Write(test.legacy, &data, 0) == ERROR_INVALID_PARAMETER);
	if (!direct)
	{
		CHECK(!create_channel(6));
		CHECK(test.legacy->Write(test.legacy, &data, 1) == CHANNEL_RC_OK && test.lastWrite == 5);
		remote_close(5);
		CHECK(flush() && test.legacy->Write(test.legacy, &data, 1) == ERROR_NOT_CONNECTED);
		CHECK(create_channel(6));
		CHECK(test.legacy->Write(test.legacy, &data, 1) == CHANNEL_RC_OK && test.lastWrite == 6);
		result = 0;
		goto cleanup;
	}
	CHECK(test.registered && test.count == 1);
	NowProtoClientCallbacksV3 callbacks = { sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_3,
		                                    nullptr,           offered,
		                                    received,          closed };
	CHECK(freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks) == ERROR_INVALID_STATE);
	callbacks.version = 2;
	CHECK(freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks) ==
	      ERROR_INVALID_PARAMETER);
	CHECK(test.legacy->Write(test.legacy, &data, 1) == ERROR_INVALID_STATE);
	NowProtoEndpoint* first = test.offers[0].endpoint;
	CHECK(first->Write(first, nullptr, 1) == ERROR_INVALID_PARAMETER);
	CHECK(first->Write(first, &data, 0) == ERROR_INVALID_PARAMETER);
	CHECK(create_channel(6));
	NowProtoEndpoint* second = test.offers[1].endpoint;
	CHECK(first != second);
	CHECK(first->Write(first, &data, 1) == CHANNEL_RC_OK && test.lastWrite == 5);
	CHECK(second->Write(second, &data, 1) == CHANNEL_RC_OK && test.lastWrite == 6);
	remote_data(5);
	remote_data(6);
	CHECK(flush() && test.offers[0].received == 1 && test.offers[1].received == 1);
	const UINT32 closes = test.closes;
	CHECK(first->Retire(first) == CHANNEL_RC_OK && first->Retire(first) == CHANNEL_RC_OK);
	CHECK(test.closes == closes && test.offers[0].closed == 0);
	CHECK(first->Write(first, &data, 1) == ERROR_NOT_CONNECTED);
	remote_data(5);
	remote_data(6);
	CHECK(flush() && test.offers[0].received == 1 && test.offers[1].received == 2);
	remote_close(5);
	CHECK(flush() && test.offers[0].closed == 1 && test.offers[1].closed == 0);
	CHECK(create_channel(5));
	CHECK(test.offers[2].endpoint != first);
	CHECK(first->Retire(first) == CHANNEL_RC_OK);
	CHECK(test.offers[2].endpoint->Write(test.offers[2].endpoint, &data, 1) == CHANNEL_RC_OK &&
	      test.lastWrite == 5);
	test.failCommand = DATA_PDU;
	CHECK(second->Write(second, &data, 1) == ERROR_WRITE_FAULT);
	CHECK(test.offers[1].closed == 0);
	test.failCommand = 0;
	CHECK(second->Write(second, &data, 1) == CHANNEL_RC_OK);
	const size_t offeredBeforeFailure = test.count;
	test.failCommand = CREATE_REQUEST_PDU;
	CHECK(!create_channel(99)); /* Accepted transport discarded before OnOpen. */
	test.failCommand = 0;
	CHECK(test.count == offeredBeforeFailure);
	test.retireInOffer = TRUE;
	CHECK(create_channel(7) && test.offers[3].closed == 0);
	CHECK(test.offers[3].endpoint->Write(test.offers[3].endpoint, &data, 1) == ERROR_NOT_CONNECTED);
	test.retireInOffer = FALSE;
	test.retireInReceive = TRUE;
	CHECK(create_channel(8));
	remote_data(8);
	CHECK(flush() && test.offers[4].received == 1 && test.offers[4].closed == 0);
	remote_data(8);
	CHECK(flush() && test.offers[4].received == 1);
	test.retireInReceive = FALSE;
	test.releaseInClosed = TRUE;
	remote_close(7);
	remote_close(8);
	CHECK(flush() && !test.offers[3].endpoint && !test.offers[4].endpoint);
	test.releaseInClosed = FALSE;

	if (!synchronous)
	{
		/* Retirement does not wait on admitted managed callbacks or hold their lock. */
		test.blockReceive = TRUE;
		remote_data(6);
		CHECK(WaitForSingleObject(test.receiveEntered, TIMEOUT) == WAIT_OBJECT_0);
		CHECK(second->Retire(second) == CHANNEL_RC_OK);
		SetEvent(test.receiveRelease);
		CHECK(flush());
		test.blockReceive = FALSE;
		CHECK(test.offers[1].received == 3 && test.offers[1].closed == 0);

		/* Force raw Write to overlap remote close. Close must wait, not free it. */
		write.endpoint = test.offers[2].endpoint;
		write.bytes = fragmented;
		write.size = sizeof(fragmented);
		test.remainingWrite = sizeof(fragmented);
		(void)InterlockedCompareExchange(&test.blockWrite, 1, 0);
		writer = CreateThread(nullptr, 0, operation, &write, 0, nullptr);
		CHECK(writer && WaitForSingleObject(test.writeEntered, TIMEOUT) == WAIT_OBJECT_0);
		remote_close(5);
		CHECK(WaitForSingleObject(write.finished, 10) == WAIT_TIMEOUT);
		SetEvent(test.writeRelease);
		CHECK(WaitForSingleObject(writer, TIMEOUT) == WAIT_OBJECT_0 &&
		      write.status == CHANNEL_RC_OK);
		CloseHandle(writer);
		writer = nullptr;
		CHECK(flush() && test.offers[2].closed == 1);
		CHECK(test.remainingWrite == 0);
		write.bytes = nullptr;
		CHECK(write.endpoint->Write(write.endpoint, &data, 1) == ERROR_NOT_CONNECTED);

		/* Retire must also wait for an in-flight write, without native closure. */
		CHECK(create_channel(9));
		write.endpoint = test.offers[test.count - 1].endpoint;
		retire.endpoint = write.endpoint;
		ResetEvent(test.writeEntered);
		ResetEvent(test.writeRelease);
		(void)InterlockedCompareExchange(&test.blockWrite, 1, 0);
		writer = CreateThread(nullptr, 0, operation, &write, 0, nullptr);
		CHECK(writer && WaitForSingleObject(test.writeEntered, TIMEOUT) == WAIT_OBJECT_0);
		retirer = CreateThread(nullptr, 0, operation, &retire, 0, nullptr);
		CHECK(retirer && WaitForSingleObject(retire.started, TIMEOUT) == WAIT_OBJECT_0);
		CHECK(WaitForSingleObject(retire.finished, 10) == WAIT_TIMEOUT);
		SetEvent(test.writeRelease);
		CHECK(WaitForSingleObject(writer, TIMEOUT) == WAIT_OBJECT_0);
		CHECK(WaitForSingleObject(retirer, TIMEOUT) == WAIT_OBJECT_0);
		CloseHandle(writer);
		CloseHandle(retirer);
		writer = retirer = nullptr;
		CHECK(write.status == CHANNEL_RC_OK && retire.status == CHANNEL_RC_OK);
		CHECK(test.offers[test.count - 1].closed == 0);
		remote_close(9);
		CHECK(flush() && test.offers[test.count - 1].closed == 1);

		for (size_t x = 0; x < 30; x++)
		{
			CHECK(create_channel(10));
			NowProtoEndpoint* endpoint = test.offers[test.count - 1].endpoint;
			PRODUCER producer = { endpoint, CreateEvent(nullptr, TRUE, FALSE, nullptr), 0 };
			CHECK(producer.started);
			HANDLE thread = CreateThread(nullptr, 0, producer_worker, &producer, 0, nullptr);
			if (!thread)
			{
				CloseHandle(producer.started);
				CHECK(thread);
			}
			const DWORD started = WaitForSingleObject(producer.started, TIMEOUT);
			if (x % 2)
				(void)endpoint->Retire(endpoint);
			remote_close(10);
			const DWORD joined = WaitForSingleObject(thread, TIMEOUT);
			CloseHandle(thread);
			CloseHandle(producer.started);
			CHECK(started == WAIT_OBJECT_0 && joined == WAIT_OBJECT_0 && producer.successes > 0);
			CHECK(flush() && test.offers[test.count - 1].closed == 1);
		}

		/* A retained writer races normal session disconnect, not arbitrary free. */
		CHECK(create_channel(11));
		write.endpoint = test.offers[test.count - 1].endpoint;
		ResetEvent(test.writeEntered);
		ResetEvent(test.writeRelease);
		(void)InterlockedCompareExchange(&test.blockWrite, 1, 0);
		writer = CreateThread(nullptr, 0, operation, &write, 0, nullptr);
		CHECK(writer && WaitForSingleObject(test.writeEntered, TIMEOUT) == WAIT_OBJECT_0);
		disconnector = CreateThread(nullptr, 0, disconnect_worker, nullptr, 0, nullptr);
		CHECK(disconnector);
		/* Observe base PostQuit closing its queue while the writer remains blocked.
		 * Ignored test-only markers have no payload or production dispatch hook. */
		BOOL stopping = FALSE;
		for (size_t x = 0; x < TIMEOUT && !stopping; x++)
		{
			stopping = !MessageQueue_Post(test.plugin->queue, nullptr, 999, nullptr, nullptr);
			if (!stopping)
				Sleep(1);
		}
		CHECK(stopping && WaitForSingleObject(disconnector, 10) == WAIT_TIMEOUT);
		SetEvent(test.writeRelease);
		CHECK(WaitForSingleObject(writer, TIMEOUT) == WAIT_OBJECT_0);
		CHECK(WaitForSingleObject(disconnector, TIMEOUT) == WAIT_OBJECT_0);
		CloseHandle(writer);
		CloseHandle(disconnector);
		writer = disconnector = nullptr;
		disconnected = TRUE;
		CHECK(write.status == CHANNEL_RC_OK && test.offers[test.count - 1].closed == 1);
		/* Same manager reconnects; no old endpoint can address a reused wire ID. */
		test.registered = FALSE;
		CHECK(install_barrier());
		test.init(test.plugin, &initHandle, CHANNEL_EVENT_CONNECTED, nullptr, 0);
		disconnected = FALSE;
		CHECK(open_barrier() && create_channel(5));
		CHECK(first->Retire(first) == CHANNEL_RC_OK &&
		      first->Write(first, &data, 1) == ERROR_NOT_CONNECTED);
		NowProtoEndpoint* fresh = test.offers[test.count - 1].endpoint;
		CHECK(fresh != first && fresh->Write(fresh, &data, 1) == CHANNEL_RC_OK);
		CHECK(test.lastWrite == 5);
	}
	result = 0;

cleanup:
	if (test.writeRelease)
		SetEvent(test.writeRelease);
	if (test.receiveRelease)
		SetEvent(test.receiveRelease);
	if (writer)
	{
		WaitForSingleObject(writer, TIMEOUT);
		CloseHandle(writer);
	}
	if (retirer)
	{
		WaitForSingleObject(retirer, TIMEOUT);
		CloseHandle(retirer);
	}
	if (disconnector)
	{
		WaitForSingleObject(disconnector, TIMEOUT);
		CloseHandle(disconnector);
		disconnected = TRUE;
	}
	if (initialized)
	{
		if (!disconnected)
			test.init(test.plugin, &initHandle, CHANNEL_EVENT_DISCONNECTED, nullptr, 0);
		test.init(test.plugin, &initHandle, CHANNEL_EVENT_TERMINATED, nullptr, 0);
		test.nativeFreed = TRUE;
	}
	for (size_t x = 0; x < test.count; x++)
	{
		NowProtoEndpoint* endpoint = test.offers[x].endpoint;
		if (test.offers[x].closed != 1)
			result = -1;
		if (endpoint)
		{
			const BYTE byte = 1;
			if (endpoint->Retire(endpoint) != CHANNEL_RC_OK ||
			    endpoint->Write(endpoint, &byte, 1) != ERROR_NOT_CONNECTED)
				result = -1;
			endpoint->Release(endpoint);
		}
	}
	if (test.failed)
		result = -1;
	freerdp_client_context_free(context);
	CloseHandle(test.writeEntered);
	CloseHandle(test.writeRelease);
	CloseHandle(test.receiveEntered);
	CloseHandle(test.receiveRelease);
	CloseHandle(test.barrier);
	CloseHandle(write.started);
	CloseHandle(write.finished);
	CloseHandle(retire.started);
	CloseHandle(retire.finished);
	DeleteCriticalSection(&test.lock);
	return result;
}

int TestNowProtoLifetime(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);
	if (sizeof(NowProtoClientContext) != 4 * sizeof(void*))
		return -1;
	if (run_case(FALSE, FALSE) != 0 || run_case(TRUE, FALSE) != 0)
		return -1;
	return run_case(TRUE, TRUE);
}
