/**
 * NOW-local allocation/ABI tests; production code compiled with local shims.
 * Licensed under the Apache License, Version 2.0.
 */

#include <freerdp/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <winpr/crt.h>
#include <winpr/synch.h>
#include <freerdp/client/nowproto.h>

static BOOL failAlloc;
static BOOL failLock;

static void* fault_calloc(size_t count, size_t size)
{
	if (failAlloc)
	{
		failAlloc = FALSE;
		return nullptr;
	}
	return calloc(count, size);
}

static BOOL fault_lock(CRITICAL_SECTION* lock, DWORD spin, DWORD flags)
{
	if (failLock)
	{
		failLock = FALSE;
		return FALSE;
	}
	return InitializeCriticalSectionEx(lock, spin, flags);
}

#define calloc fault_calloc
#define InitializeCriticalSectionEx fault_lock
#define freerdp_nowproto_client_set_callbacks local_set_callbacks
#define nowproto_DVCPluginEntry local_nowproto_entry
#include "../nowproto_main.c"
#undef calloc
#undef InitializeCriticalSectionEx

#define CHECK(condition)                                                    \
	do                                                                      \
	{                                                                       \
		if (!(condition))                                                   \
		{                                                                   \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
			goto cleanup;                                                   \
		}                                                                   \
	} while (0)

static size_t offers, receives, closures, writes;
static NowProtoEndpoint* retained;
static BOOL nativeGone;

static void offered(WINPR_ATTR_UNUSED void* custom, NowProtoEndpoint* endpoint)
{
	offers++;
	endpoint->Retain(endpoint);
	retained = endpoint;
}

static void received(WINPR_ATTR_UNUSED void* custom, WINPR_ATTR_UNUSED NowProtoEndpoint* endpoint,
                     WINPR_ATTR_UNUSED const BYTE* data, WINPR_ATTR_UNUSED size_t size)
{
	receives++;
}

static void closed(WINPR_ATTR_UNUSED void* custom, WINPR_ATTR_UNUSED NowProtoEndpoint* endpoint)
{
	closures++;
}

static UINT transport_write(WINPR_ATTR_UNUSED IWTSVirtualChannel* channel, ULONG size,
                            const BYTE* data, WINPR_ATTR_UNUSED void* reserved)
{
	if (nativeGone || !data || !size)
		return ERROR_INVALID_STATE;
	writes++;
	return ERROR_WRITE_FAULT;
}

static UINT transport_close(WINPR_ATTR_UNUSED IWTSVirtualChannel* channel)
{
	/* No path in this prototype may request native Close. */
	return ERROR_INVALID_STATE;
}

int TestNowProtoFaults(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);
	int result = -1;
	IWTSVirtualChannel transport = { transport_write, transport_close };
	IWTSVirtualChannelCallback* callback = nullptr;
	NOWPROTO_PLUGIN plugin = { 0 };
	if (!InitializeCriticalSectionEx(&plugin.lock, 0, 0))
		return -1;
	plugin.context.handle = &plugin;
	NowProtoClientCallbacksV3 callbacks = { sizeof(callbacks), NOWPROTO_CLIENT_CALLBACKS_VERSION_3,
		                                    nullptr,           offered,
		                                    received,          closed };
	offers = receives = closures = writes = 0;
	nativeGone = FALSE;
	retained = nullptr;
	CHECK(local_set_callbacks(nullptr, &callbacks) == ERROR_INVALID_PARAMETER);
	CHECK(local_set_callbacks(&plugin.context, nullptr) == ERROR_INVALID_PARAMETER);
	callbacks.version = 2;
	CHECK(local_set_callbacks(&plugin.context, &callbacks) == ERROR_INVALID_PARAMETER);
	callbacks.version = NOWPROTO_CLIENT_CALLBACKS_VERSION_3;
	callbacks.size--;
	CHECK(local_set_callbacks(&plugin.context, &callbacks) == ERROR_INVALID_PARAMETER);
	callbacks.size++;
	callbacks.Closed = nullptr;
	CHECK(local_set_callbacks(&plugin.context, &callbacks) == ERROR_INVALID_PARAMETER);
	callbacks.Closed = closed;
	CHECK(local_set_callbacks(&plugin.context, &callbacks) == CHANNEL_RC_OK);
	CHECK(local_set_callbacks(&plugin.context, &callbacks) == ERROR_INVALID_STATE);
	memset(&callbacks, 0, sizeof(callbacks)); /* Registration copies its input. */

	BOOL accept = TRUE;
	failAlloc = TRUE;
	CHECK(nowproto_on_new_channel(&plugin.listenerCallback, &transport, nullptr, &accept,
	                              &callback) == CHANNEL_RC_NO_MEMORY);
	CHECK(!accept && !callback && !plugin.current);
	failLock = TRUE;
	CHECK(nowproto_on_new_channel(&plugin.listenerCallback, &transport, nullptr, &accept,
	                              &callback) == CHANNEL_RC_NO_MEMORY);
	CHECK(!accept && !callback && !plugin.current);
	CHECK(nowproto_on_new_channel(&plugin.listenerCallback, &transport, nullptr, &accept,
	                              &callback) == CHANNEL_RC_OK);
	CHECK(accept && callback && plugin.current);
	CHECK(callback->OnOpen(callback) == CHANNEL_RC_OK && offers == 1 && retained);
	const BYTE data = 1;
	CHECK(retained->Write(retained, &data, 0) == ERROR_INVALID_PARAMETER && !writes);
	CHECK(retained->Write(retained, nullptr, 1) == ERROR_INVALID_PARAMETER && !writes);
	CHECK(retained->Write(retained, &data, 1) == ERROR_WRITE_FAULT && writes == 1);
	CHECK(retained->Retire(retained) == CHANNEL_RC_OK && closures == 0);
	CHECK(retained->Write(retained, &data, 1) == ERROR_NOT_CONNECTED && writes == 1);
	wStream* stream = Stream_New(nullptr, 1);
	CHECK(stream);
	const UINT receiveStatus = callback->OnDataReceived(callback, stream);
	Stream_Free(stream, TRUE);
	CHECK(receiveStatus == CHANNEL_RC_OK && receives == 0);
	CHECK(callback->OnClose(callback) == CHANNEL_RC_OK);
	callback = nullptr;
	nativeGone = TRUE;
	CHECK(!plugin.current && closures == 1);
	CHECK(retained->Retire(retained) == CHANNEL_RC_OK);
	CHECK(retained->Write(retained, &data, 1) == ERROR_NOT_CONNECTED && writes == 1);
	CHECK(nowproto_channel(retained)->plugin == nullptr);
	retained->Release(retained);
	retained = nullptr;

	/* A channel can be discarded before OnOpen (e.g. failed CREATE send). */
	CHECK(nowproto_on_new_channel(&plugin.listenerCallback, &transport, nullptr, &accept,
	                              &callback) == CHANNEL_RC_OK);
	CHECK(callback->OnClose(callback) == CHANNEL_RC_OK);
	callback = nullptr;
	CHECK(closures == 1 && offers == 1 && !plugin.current);
	result = 0;

cleanup:
	if (callback)
		callback->OnClose(callback);
	if (retained)
		retained->Release(retained);
	DeleteCriticalSection(&plugin.lock);
	return result;
}
