#include <freerdp/config.h>

#include <winpr/crt.h>
#include <winpr/interlocked.h>
#include <winpr/synch.h>

#include <freerdp/channels/log.h>

#include "nowproto_main.h"

#define TAG CHANNELS_TAG("nowproto.client")

typedef struct s_nowproto_channel NOWPROTO_CHANNEL;

typedef struct
{
	IWTSPlugin iface;
	IWTSListenerCallback listenerCallback;
	IWTSListener* listener;
	IWTSVirtualChannelManager* manager;
	NowProtoClientContext context;
	CRITICAL_SECTION lock;
	NowProtoClientCallbacksV3 callbacks;
	NOWPROTO_CHANNEL* current;
	BOOL opened;
} NOWPROTO_PLUGIN;

struct s_nowproto_channel
{
	IWTSVirtualChannelCallback iface;
	NowProtoEndpoint endpoint;
	volatile LONG refs;
	NOWPROTO_PLUGIN* plugin; /* Native callbacks only; never retained after OnClose. */
	CRITICAL_SECTION lock;
	IWTSVirtualChannel* transport; /* Protected by lock through the entire Write. */
	volatile LONG retired;
	NowProtoClientCallbacksV3 callbacks;
	BOOL offered;
};

static NOWPROTO_CHANNEL* nowproto_channel(NowProtoEndpoint* endpoint)
{
	return CONTAINING_RECORD(endpoint, NOWPROTO_CHANNEL, endpoint);
}

static void nowproto_retain(NowProtoEndpoint* endpoint)
{
	InterlockedIncrement(&nowproto_channel(endpoint)->refs);
}

static void nowproto_release(NowProtoEndpoint* endpoint)
{
	NOWPROTO_CHANNEL* channel = nowproto_channel(endpoint);
	if (InterlockedDecrement(&channel->refs) == 0)
	{
		DeleteCriticalSection(&channel->lock);
		free(channel);
	}
}

static UINT nowproto_endpoint_write(NowProtoEndpoint* endpoint, const BYTE* data, UINT32 size)
{
	if (!data || !size)
		return ERROR_INVALID_PARAMETER;
	NOWPROTO_CHANNEL* channel = nowproto_channel(endpoint);
	if (InterlockedCompareExchange(&channel->retired, 0, 0))
		return ERROR_NOT_CONNECTED;
	UINT status = ERROR_NOT_CONNECTED;
	EnterCriticalSection(&channel->lock);
	if (channel->transport && !InterlockedCompareExchange(&channel->retired, 0, 0))
	{
		/* Nonempty Write cannot call OnClose on this branch. It takes no channel
		 * table lock. OnClose waits here before allowing core to free transport. */
		status = channel->transport->Write(channel->transport, size, data, nullptr);
	}
	LeaveCriticalSection(&channel->lock);
	if (status != CHANNEL_RC_OK && status != ERROR_NOT_CONNECTED)
		WLog_ERR(TAG, "NOW Write failed: %" PRIu32, status);
	return status;
}

static UINT nowproto_endpoint_retire(NowProtoEndpoint* endpoint)
{
	NOWPROTO_CHANNEL* channel = nowproto_channel(endpoint);
	/* Close admission before waiting for a writer, so repeated submissions cannot
	 * keep entering while retirement/native close waits for the lifetime gate. */
	(void)InterlockedCompareExchange(&channel->retired, 1, 0);
	EnterCriticalSection(&channel->lock);
	LeaveCriticalSection(&channel->lock);
	return CHANNEL_RC_OK;
}

static UINT nowproto_write(NowProtoClientContext* context, void* data, int size)
{
	if (!context || (size <= 0) || !data)
		return ERROR_INVALID_PARAMETER;
	NOWPROTO_PLUGIN* plugin = context->handle;
	EnterCriticalSection(&plugin->lock);
	NOWPROTO_CHANNEL* channel = plugin->current;
	const BOOL direct = plugin->callbacks.version != 0;
	if (channel && !direct)
		nowproto_retain(&channel->endpoint);
	LeaveCriticalSection(&plugin->lock);
	if (direct)
		return ERROR_INVALID_STATE;
	if (!channel)
		return ERROR_NOT_CONNECTED;
	const UINT status = nowproto_endpoint_write(&channel->endpoint, data, (UINT32)size);
	nowproto_release(&channel->endpoint);
	return status;
}

UINT freerdp_nowproto_client_set_callbacks(NowProtoClientContext* context,
                                           const NowProtoClientCallbacksV3* callbacks)
{
	if (!context || !callbacks || (callbacks->size != sizeof(*callbacks)) ||
	    (callbacks->version != NOWPROTO_CLIENT_CALLBACKS_VERSION_3) || !callbacks->Offer ||
	    !callbacks->Receive || !callbacks->Closed)
		return ERROR_INVALID_PARAMETER;
	NOWPROTO_PLUGIN* plugin = context->handle;
	EnterCriticalSection(&plugin->lock);
	UINT status = ERROR_INVALID_STATE;
	if (!plugin->opened && !plugin->callbacks.version)
	{
		plugin->callbacks = *callbacks;
		status = CHANNEL_RC_OK;
	}
	LeaveCriticalSection(&plugin->lock);
	return status;
}

static UINT nowproto_on_open(IWTSVirtualChannelCallback* callback)
{
	NOWPROTO_CHANNEL* channel = (NOWPROTO_CHANNEL*)callback;
	NOWPROTO_PLUGIN* plugin = channel->plugin;
	EnterCriticalSection(&plugin->lock);
	plugin->opened = TRUE;
	channel->callbacks = plugin->callbacks;
	channel->offered = channel->callbacks.version != 0;
	LeaveCriticalSection(&plugin->lock);
	if (channel->offered)
		channel->callbacks.Offer(channel->callbacks.custom, &channel->endpoint);
	return CHANNEL_RC_OK;
}

static UINT nowproto_on_data_received(IWTSVirtualChannelCallback* callback, wStream* data)
{
	NOWPROTO_CHANNEL* channel = (NOWPROTO_CHANNEL*)callback;
	const BOOL deliver = !InterlockedCompareExchange(&channel->retired, 0, 0);
	if (!deliver)
		return CHANNEL_RC_OK;
	if (channel->offered)
	{
		channel->callbacks.Receive(channel->callbacks.custom, &channel->endpoint,
		                           Stream_Pointer(data), Stream_GetRemainingLength(data));
		return CHANNEL_RC_OK;
	}
	NowProtoClientContext* context = &channel->plugin->context;
	if (context->Read)
		return context->Read(context, Stream_Pointer(data), Stream_GetRemainingLength(data));
	return CHANNEL_RC_OK;
}

static UINT nowproto_on_close(IWTSVirtualChannelCallback* callback)
{
	NOWPROTO_CHANNEL* channel = (NOWPROTO_CHANNEL*)callback;
	NOWPROTO_PLUGIN* plugin = channel->plugin;
	/* Core calls OnClose before freeing its channel, including table teardown.
	 * This gate waits out nonempty writes without ever acquiring a core lock. */
	(void)InterlockedCompareExchange(&channel->retired, 1, 0);
	EnterCriticalSection(&channel->lock);
	channel->transport = nullptr;
	channel->plugin = nullptr;
	LeaveCriticalSection(&channel->lock);
	EnterCriticalSection(&plugin->lock);
	if (plugin->current == channel)
		plugin->current = nullptr;
	LeaveCriticalSection(&plugin->lock);
	if (channel->offered)
		channel->callbacks.Closed(channel->callbacks.custom, &channel->endpoint);
	nowproto_release(&channel->endpoint);
	return CHANNEL_RC_OK;
}

static UINT nowproto_on_new_channel(IWTSListenerCallback* callback, IWTSVirtualChannel* transport,
                                    WINPR_ATTR_UNUSED BYTE* data, BOOL* accept,
                                    IWTSVirtualChannelCallback** result)
{
	NOWPROTO_PLUGIN* plugin = CONTAINING_RECORD(callback, NOWPROTO_PLUGIN, listenerCallback);
	*accept = FALSE;
	*result = nullptr;
	EnterCriticalSection(&plugin->lock);
	const BOOL busy = plugin->current && !plugin->callbacks.version;
	LeaveCriticalSection(&plugin->lock);
	if (busy)
		return ERROR_DEVICE_ALREADY_ATTACHED;
	NOWPROTO_CHANNEL* channel = calloc(1, sizeof(*channel));
	if (!channel)
		return CHANNEL_RC_NO_MEMORY;
	if (!InitializeCriticalSectionEx(&channel->lock, 0, 0))
	{
		free(channel);
		return CHANNEL_RC_NO_MEMORY;
	}
	channel->transport = transport;
	channel->iface.OnDataReceived = nowproto_on_data_received;
	channel->iface.OnOpen = nowproto_on_open;
	channel->iface.OnClose = nowproto_on_close;
	channel->endpoint.Retain = nowproto_retain;
	channel->endpoint.Release = nowproto_release;
	channel->endpoint.Write = nowproto_endpoint_write;
	channel->endpoint.Retire = nowproto_endpoint_retire;
	channel->refs = 1; /* Owned by the native callback until OnClose. */
	channel->plugin = plugin;
	EnterCriticalSection(&plugin->lock);
	plugin->current = channel;
	LeaveCriticalSection(&plugin->lock);
	*accept = TRUE;
	*result = &channel->iface;
	return CHANNEL_RC_OK;
}

static UINT nowproto_initialize(IWTSPlugin* iface, IWTSVirtualChannelManager* manager)
{
	NOWPROTO_PLUGIN* plugin = (NOWPROTO_PLUGIN*)iface;
	if (!manager || plugin->manager)
		return ERROR_INVALID_STATE;
	IWTSListener* listener = nullptr;
	const UINT status = manager->CreateListener(manager, NOWPROTO_DVC_CHANNEL_NAME, 0,
	                                            &plugin->listenerCallback, &listener);
	if (status == CHANNEL_RC_OK)
	{
		plugin->manager = manager;
		plugin->listener = listener;
		plugin->listener->pInterface = &plugin->context;
	}
	return status;
}

static UINT nowproto_terminated(IWTSPlugin* iface)
{
	NOWPROTO_PLUGIN* plugin = (NOWPROTO_PLUGIN*)iface;
	/* Base drdynvc calls every channel's OnClose before terminating plugins. */
	if (plugin->listener)
	{
		const UINT status = plugin->manager->DestroyListener(plugin->manager, plugin->listener);
		if (status != CHANNEL_RC_OK)
			WLog_ERR(TAG, "DestroyListener failed: %" PRIu32, status);
	}
	DeleteCriticalSection(&plugin->lock);
	free(plugin);
	return CHANNEL_RC_OK;
}

FREERDP_ENTRY_POINT(UINT VCAPITYPE nowproto_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* entry))
{
	if (!entry || !entry->GetPlugin || !entry->RegisterPlugin)
		return ERROR_INVALID_PARAMETER;
	if (entry->GetPlugin(entry, NOWPROTO_DVC_CHANNEL_NAME))
		return CHANNEL_RC_ALREADY_INITIALIZED;
	NOWPROTO_PLUGIN* plugin = calloc(1, sizeof(*plugin));
	if (!plugin)
		return CHANNEL_RC_NO_MEMORY;
	if (!InitializeCriticalSectionEx(&plugin->lock, 0, 0))
	{
		free(plugin);
		return CHANNEL_RC_NO_MEMORY;
	}
	plugin->iface.Initialize = nowproto_initialize;
	plugin->iface.Terminated = nowproto_terminated;
	plugin->iface.pInterface = &plugin->context;
	plugin->context.handle = plugin;
	plugin->context.Write = nowproto_write;
	plugin->listenerCallback.OnNewChannelConnection = nowproto_on_new_channel;
	const UINT status = entry->RegisterPlugin(entry, NOWPROTO_DVC_CHANNEL_NAME, &plugin->iface);
	if (status != CHANNEL_RC_OK)
		nowproto_terminated(&plugin->iface);
	return status;
}
