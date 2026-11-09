/**
 * NOW endpoint lifetime tests through the real drdynvc PDU dispatch.
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
#define MAX_OFFERS 512
#define CHECK(condition)                                                    \
	do                                                                      \
	{                                                                       \
		if (!(condition))                                                   \
		{                                                                   \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
			goto disconnect;                                                \
		}                                                                   \
	} while (0)

typedef struct
{
	PCHANNEL_INIT_EVENT_EX_FN init;
	PCHANNEL_OPEN_EVENT_EX_FN event;
	void* plugin;
	NowProtoClientContext* legacy;
	NowProtoEndpoint* offers[MAX_OFFERS];
	size_t count;
	size_t received[MAX_OFFERS];
	size_t closed[MAX_OFFERS];
	volatile LONG failed;
	BOOL direct;
	BOOL closeInOffer;
	BOOL closeInReceive;
	BOOL releaseInClosed;
	BOOL crossClose;
	BOOL tearingDown;
	BOOL haveStatus;
	INT32 createStatus;
	UINT32 lastWrite;
	UINT32 lastClose;
	UINT32 writes;
	UINT32 closes;
	volatile LONG workerStarted;
	volatile LONG workerStop;
	NowProtoEndpoint* workerEndpoint;
	volatile LONG blockWrite;
	volatile LONG closerStarted;
	BOOL remoteCloser;
	HANDLE writeEntered;
	HANDLE writeRelease;
	UINT failCommand;
} TEST_NOW;

static TEST_NOW test;
static int initHandle;

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
	if (data && length >= 2)
	{
		const BYTE command = data[0] >> 4;
		if (test.failCommand == command)
			return ERROR_WRITE_FAULT;
		if ((command == CREATE_REQUEST_PDU) && (length == 6))
		{
			test.createStatus = (INT32)(data[2] | ((UINT32)data[3] << 8) | ((UINT32)data[4] << 16) |
			                            ((UINT32)data[5] << 24));
			test.haveStatus = TRUE;
		}
		else if ((command == DATA_PDU) || (command == DATA_FIRST_PDU))
		{
			test.lastWrite = pdu_id(data);
			test.writes++;
			if (InterlockedCompareExchange(&test.blockWrite, 0, 1) == 1)
			{
				SetEvent(test.writeEntered);
				if (WaitForSingleObject(test.writeRelease, 10000) != WAIT_OBJECT_0)
					InterlockedCompareExchange(&test.failed, 1, 0);
			}
		}
		else if (command == CLOSE_REQUEST_PDU)
		{
			test.lastClose = pdu_id(data);
			test.closes++;
		}
	}
	test.event(test.plugin, openHandle, CHANNEL_EVENT_WRITE_COMPLETE, user, 0, 0, 0);
	return CHANNEL_RC_OK;
}

static size_t index_of(NowProtoEndpoint* endpoint)
{
	for (size_t x = 0; x < test.count; x++)
	{
		if (test.offers[x] == endpoint)
			return x;
	}
	InterlockedCompareExchange(&test.failed, 1, 0);
	return MAX_OFFERS;
}

static void offered(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint)
{
	if (test.count == MAX_OFFERS)
	{
		InterlockedCompareExchange(&test.failed, 1, 0);
		return;
	}
	endpoint->Retain(endpoint);
	test.offers[test.count++] = endpoint;
	if (test.closeInOffer && endpoint->Close(endpoint) != CHANNEL_RC_OK)
		InterlockedCompareExchange(&test.failed, 1, 0);
}

static void received(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint, const BYTE* data,
                     size_t size)
{
	const size_t index = index_of(endpoint);
	if (index == MAX_OFFERS)
		return;
	test.received[index]++;
	if ((size != 1) || (data[0] != 0x42))
		InterlockedCompareExchange(&test.failed, 1, 0);
	if (test.closeInReceive && endpoint->Close(endpoint) != CHANNEL_RC_OK)
		InterlockedCompareExchange(&test.failed, 1, 0);
}

static void closed(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint)
{
	const size_t index = index_of(endpoint);
	if (index == MAX_OFFERS)
		return;
	test.closed[index]++;
	const BYTE data = 1;
	if ((endpoint->Close(endpoint) != CHANNEL_RC_OK) ||
	    (endpoint->Write(endpoint, &data, 1) != ERROR_NOT_CONNECTED))
		InterlockedCompareExchange(&test.failed, 1, 0);
	if (test.crossClose && test.count > 1)
	{
		const size_t next = (index + 1) % test.count;
		NowProtoEndpoint* other = test.offers[next];
		const size_t before = test.closed[next];
		if (other)
		{
			if (other->Close(other) != CHANNEL_RC_OK)
				InterlockedCompareExchange(&test.failed, 1, 0);
			if (test.tearingDown && ((test.closed[next] != before) ||
			                         (other->Write(other, &data, 1) != ERROR_NOT_CONNECTED)))
				InterlockedCompareExchange(&test.failed, 1, 0);
		}
	}
	if (test.releaseInClosed)
	{
		test.offers[index] = nullptr;
		endpoint->Release(endpoint);
	}
}

static UINT connected(WINPR_ATTR_UNUSED DrdynvcClientContext* context, const char* name,
                      void* iface)
{
	if (strcmp(name, NOWPROTO_DVC_CHANNEL_NAME) != 0)
		return CHANNEL_RC_OK;
	test.legacy = iface;
	if (test.direct && !test.count)
	{
		const NowProtoClientCallbacksV2 callbacks = {
			sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_2,
			nullptr,           offered,
			received,          closed
		};
		return freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks);
	}
	return CHANNEL_RC_OK;
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
	test.haveStatus = FALSE;
	receive_pdu(pdu, (UINT32)(size + 2));
	return test.haveStatus && (test.createStatus == 0);
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

static DWORD WINAPI write_worker(WINPR_ATTR_UNUSED void* arg)
{
	const BYTE data = 0x43;
	NowProtoEndpoint* endpoint = test.workerEndpoint;
	InterlockedCompareExchange(&test.workerStarted, 1, 0);
	do
	{
		UINT status = endpoint->Write(endpoint, &data, sizeof(data));
		if ((status != CHANNEL_RC_OK) && (status != ERROR_NOT_CONNECTED))
			InterlockedCompareExchange(&test.failed, 1, 0);
	} while (!InterlockedCompareExchange(&test.workerStop, 0, 0));
	endpoint->Release(endpoint);
	return 0;
}

static DWORD WINAPI close_worker(WINPR_ATTR_UNUSED void* arg)
{
	InterlockedCompareExchange(&test.closerStarted, 1, 0);
	if (test.remoteCloser)
		remote_close(9);
	else if (test.workerEndpoint->Close(test.workerEndpoint) != CHANNEL_RC_OK)
		InterlockedCompareExchange(&test.failed, 1, 0);
	return 0;
}

static BOOL start_worker(NowProtoEndpoint* endpoint, HANDLE* thread)
{
	test.workerEndpoint = endpoint;
	test.workerStarted = 0;
	test.workerStop = 0;
	endpoint->Retain(endpoint);
	*thread = CreateThread(nullptr, 0, write_worker, nullptr, 0, nullptr);
	if (!*thread)
	{
		endpoint->Release(endpoint);
		return FALSE;
	}
	for (size_t x = 0; x < 1000; x++)
	{
		if (InterlockedCompareExchange(&test.workerStarted, 0, 0))
			return TRUE;
		Sleep(1);
	}
	return FALSE;
}

static BOOL stop_worker(HANDLE* thread)
{
	if (!*thread)
		return TRUE;
	InterlockedCompareExchange(&test.workerStop, 1, 0);
	const DWORD status = WaitForSingleObject(*thread, 10000);
	CloseHandle(*thread);
	*thread = nullptr;
	return status == WAIT_OBJECT_0;
}

static int run_case(BOOL direct)
{
	int result = -1;
	HANDLE worker = nullptr;
	HANDLE closer = nullptr;
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);
	entry.ContextSize = sizeof(rdpClientContext);
	memset(&test, 0, sizeof(test));
	test.direct = direct;
	rdpContext* context = freerdp_client_context_new(&entry);
	if (!context)
		return -1;

	const char* channels[] = { "nowproto" };
	if (!freerdp_settings_set_bool(context->settings, FreeRDP_SynchronousDynamicChannels, TRUE) ||
	    !freerdp_client_add_dynamic_channel(context->settings, 1, channels))
		goto cleanup;
	PVIRTUALCHANNELENTRYEX pluginEntry =
	    WINPR_FUNC_PTR_CAST(freerdp_channels_load_static_addin_entry(
	                            DRDYNVC_SVC_CHANNEL_NAME, nullptr, nullptr,
	                            FREERDP_ADDIN_CHANNEL_STATIC | FREERDP_ADDIN_CHANNEL_ENTRYEX),
	                        PVIRTUALCHANNELENTRYEX);
	if (!pluginEntry)
		goto cleanup;
	CHANNEL_ENTRY_POINTS_FREERDP_EX points = WINPR_C_ARRAY_INIT;
	points.cbSize = sizeof(points);
	points.protocolVersion = VIRTUAL_CHANNEL_VERSION_WIN2000;
	points.pVirtualChannelInitEx = init_ex;
	points.pVirtualChannelOpenEx = open_ex;
	points.pVirtualChannelCloseEx = close_ex;
	points.pVirtualChannelWriteEx = write_ex;
	points.MagicNumber = FREERDP_CHANNEL_MAGIC_NUMBER;
	points.context = context;
	if (!pluginEntry((PCHANNEL_ENTRY_POINTS_EX)&points, &initHandle) || !test.init)
		goto cleanup;
	((drdynvcPlugin*)test.plugin)->context->OnChannelConnected = connected;
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_INITIALIZED, nullptr, 0);
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_CONNECTED, nullptr, 0);
	CHECK(test.event);
	CHECK(create_channel(5));
	const BYTE data = 0x43;
	CHECK(test.legacy);
	CHECK(test.legacy->Write(test.legacy, nullptr, -1) == ERROR_INVALID_PARAMETER);

	if (!direct)
	{
		const NowProtoClientCallbacksV2 callbacks = {
			sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_2,
			nullptr,           offered,
			received,          closed
		};
		CHECK(freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks) ==
		      ERROR_INVALID_STATE);
		CHECK(!create_channel(6));
		CHECK(test.legacy->Write(test.legacy, (void*)&data, 1) == CHANNEL_RC_OK);
		CHECK(test.lastWrite == 5);
		remote_close(5);
		CHECK(test.legacy->Write(test.legacy, (void*)&data, 1) == ERROR_NOT_CONNECTED);
		CHECK(create_channel(6));
		CHECK(test.legacy->Write(test.legacy, (void*)&data, 1) == CHANNEL_RC_OK);
		CHECK(test.lastWrite == 6);
		result = 0;
		goto disconnect;
	}

	CHECK(test.count == 1);
	NowProtoClientCallbacksV2 callbacks = { sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_2,
		                                    nullptr,           offered,
		                                    received,          closed };
	CHECK(freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks) == ERROR_INVALID_STATE);
	callbacks.version = 100;
	CHECK(freerdp_nowproto_client_set_callbacks(test.legacy, &callbacks) ==
	      ERROR_INVALID_PARAMETER);
	CHECK(test.legacy->Write(test.legacy, (void*)&data, 1) == ERROR_INVALID_STATE);
	CHECK(test.offers[0]->Write(test.offers[0], nullptr, 1) == ERROR_INVALID_PARAMETER);
	CHECK(test.offers[0]->Write(test.offers[0], &data, 0) == ERROR_INVALID_PARAMETER);
	CHECK(create_channel(6)); /* Replacement while the first endpoint is still open. */
	CHECK(test.count == 2 && test.offers[0] != test.offers[1]);
	CHECK(test.offers[0]->Write(test.offers[0], &data, 1) == CHANNEL_RC_OK);
	CHECK(test.lastWrite == 5);
	CHECK(test.offers[1]->Write(test.offers[1], &data, 1) == CHANNEL_RC_OK);
	CHECK(test.lastWrite == 6);
	remote_data(5);
	remote_data(6);
	CHECK(test.received[0] == 1 && test.received[1] == 1);
	remote_close(5);
	CHECK(test.closed[0] == 1 && test.closed[1] == 0);
	CHECK(test.offers[0]->Close(test.offers[0]) == CHANNEL_RC_OK);
	CHECK(test.offers[0]->Write(test.offers[0], &data, 1) == ERROR_NOT_CONNECTED);
	CHECK(test.offers[1]->Write(test.offers[1], &data, 1) == CHANNEL_RC_OK);
	CHECK(test.lastWrite == 6);
	CHECK(create_channel(5)); /* Reused wire ID is not a reused endpoint. */
	CHECK(test.offers[0]->Close(test.offers[0]) == CHANNEL_RC_OK);
	CHECK(test.offers[2]->Write(test.offers[2], &data, 1) == CHANNEL_RC_OK);
	CHECK(test.lastWrite == 5);
	CHECK(test.offers[2]->Close(test.offers[2]) == CHANNEL_RC_OK);
	CHECK(test.lastClose == 5 && test.closed[2] == 1);
	const UINT32 closes = test.closes;
	CHECK(test.offers[2]->Close(test.offers[2]) == CHANNEL_RC_OK);
	CHECK(test.closes == closes && test.closed[2] == 1);

	test.closeInOffer = TRUE;
	test.releaseInClosed = TRUE;
	CHECK(create_channel(7)); /* Closed reenters Offer and releases consumer reference. */
	CHECK(test.closed[3] == 1 && !test.offers[3]);
	test.closeInOffer = FALSE;
	test.closeInReceive = TRUE;
	CHECK(create_channel(8));
	remote_data(8);
	CHECK(test.received[4] == 1 && test.closed[4] == 1 && !test.offers[4]);
	test.closeInReceive = FALSE;
	CHECK(create_channel(15));
	NowProtoEndpoint* releasedOnClose = test.offers[test.count - 1];
	CHECK(releasedOnClose->Close(releasedOnClose) == CHANNEL_RC_OK);
	CHECK(test.closed[test.count - 1] == 1 && !test.offers[test.count - 1]);
	test.releaseInClosed = FALSE;

	CHECK(create_channel(12));
	NowProtoEndpoint* failing = test.offers[test.count - 1];
	test.failCommand = DATA_PDU;
	CHECK(failing->Write(failing, &data, 1) == ERROR_WRITE_FAULT);
	CHECK(test.closed[test.count - 1] == 0);
	test.failCommand = CLOSE_REQUEST_PDU;
	CHECK(failing->Close(failing) == ERROR_WRITE_FAULT);
	CHECK(test.closed[test.count - 1] == 1);
	test.failCommand = 0;
	CHECK(failing->Close(failing) == CHANNEL_RC_OK);

	test.writeEntered = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	test.writeRelease = CreateEvent(nullptr, TRUE, FALSE, nullptr);
	CHECK(test.writeEntered && test.writeRelease);
	/* Force the closer to contend while Write is inside the native transport. */
	for (size_t x = 0; x < 2; x++)
	{
		CHECK(create_channel(9));
		NowProtoEndpoint* endpoint = test.offers[test.count - 1];
		ResetEvent(test.writeEntered);
		ResetEvent(test.writeRelease);
		test.blockWrite = 1;
		CHECK(start_worker(endpoint, &worker));
		CHECK(WaitForSingleObject(test.writeEntered, 10000) == WAIT_OBJECT_0);
		test.closerStarted = 0;
		test.remoteCloser = x == 0;
		closer = CreateThread(nullptr, 0, close_worker, nullptr, 0, nullptr);
		CHECK(closer);
		for (size_t y = 0; y < 1000 && !InterlockedCompareExchange(&test.closerStarted, 0, 0); y++)
			Sleep(1);
		CHECK(InterlockedCompareExchange(&test.closerStarted, 0, 0));
		SetEvent(test.writeRelease);
		CHECK(WaitForSingleObject(closer, 10000) == WAIT_OBJECT_0);
		CloseHandle(closer);
		closer = nullptr;
		CHECK(stop_worker(&worker));
		CHECK(test.closed[test.count - 1] == 1);
	}

	/* Race real transport writes with remote close, then with local close. */
	for (size_t x = 0; x < 40; x++)
	{
		CHECK(create_channel(9));
		NowProtoEndpoint* endpoint = test.offers[test.count - 1];
		CHECK(start_worker(endpoint, &worker));
		if (x % 2)
			CHECK(endpoint->Close(endpoint) == CHANNEL_RC_OK);
		else
			remote_close(9);
		CHECK(stop_worker(&worker));
		CHECK(test.closed[test.count - 1] == 1);
		CHECK(endpoint->Write(endpoint, &data, 1) == ERROR_NOT_CONNECTED);
	}

	CHECK(create_channel(10));
	CHECK(create_channel(11));
	/* Reentrant cross-close during HashTable_Clear must not mutate its iteration. */
	test.crossClose = TRUE;
	CHECK(start_worker(test.offers[test.count - 1], &worker));
	result = 0;

disconnect:
	if (test.writeRelease)
		SetEvent(test.writeRelease);
	if (closer)
	{
		if (WaitForSingleObject(closer, 10000) != WAIT_OBJECT_0)
			result = -1;
		CloseHandle(closer);
	}
	test.tearingDown = TRUE;
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_DISCONNECTED, nullptr, 0);
	test.init(test.plugin, &initHandle, CHANNEL_EVENT_TERMINATED, nullptr, 0);
	if (!stop_worker(&worker))
		result = -1;
	if (test.writeEntered)
		CloseHandle(test.writeEntered);
	if (test.writeRelease)
		CloseHandle(test.writeRelease);
	for (size_t x = 0; x < test.count; x++)
	{
		NowProtoEndpoint* endpoint = test.offers[x];
		if ((test.closed[x] != 1) || (test.received[x] > 1))
			result = -1;
		if (endpoint)
		{
			if ((endpoint->Close(endpoint) != CHANNEL_RC_OK) ||
			    (endpoint->Write(endpoint, (const BYTE*)"x", 1) != ERROR_NOT_CONNECTED))
				result = -1;
			endpoint->Release(endpoint);
		}
	}
	if (test.failed)
		result = -1;
cleanup:
	freerdp_client_context_free(context);
	return result;
}

int TestNowProtoLifetime(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);
	/* Legacy layout must remain exactly the four pointers used by NativeSessions. */
	if (sizeof(NowProtoClientContext) != 4 * sizeof(void*))
		return -1;
	if (run_case(FALSE) != 0)
		return -1;
	return run_case(TRUE);
}
