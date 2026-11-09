#include <freerdp/config.h>

#include <winpr/crt.h>
#include <winpr/interlocked.h>
#include <winpr/synch.h>

#include <freerdp/channels/log.h>
#include <freerdp/client/drdynvc.h>

#include "nowproto_main.h"

#define TAG CHANNELS_TAG("nowproto.client")

typedef struct s_nowproto_channel NOWPROTO_CHANNEL;

typedef struct
{
	IWTSPlugin iface;
	IWTSListenerCallback listenerCallback;
	IWTSListener* listener;
	IWTSVirtualChannelManager* manager;
	DrdynvcDispatcher* dispatcher;
	NowProtoClientContext context;
	CRITICAL_SECTION lock;
	NowProtoClientCallbacksV2 callbacks;
	NOWPROTO_CHANNEL* current;
	BOOL opened;
} NOWPROTO_PLUGIN;

struct s_nowproto_channel
{
	IWTSVirtualChannelCallback iface;
	NowProtoEndpoint endpoint;
	volatile LONG refs;
	NOWPROTO_PLUGIN* plugin;
	DrdynvcDispatcher* dispatcher;
	IWTSVirtualChannel* transport; /* Only the DVC worker touches this in V2. */
	volatile LONG closed;
	NowProtoClientCallbacksV2 callbacks;
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
		freerdp_drdynvc_dispatcher_release(channel->dispatcher);
		free(channel);
	}
}

typedef struct
{
	NOWPROTO_CHANNEL* channel;
	void* token;
	UINT32 size;
	BOOL close;
	BYTE data[];
} NOWPROTO_COMMAND;

static UINT nowproto_command_run(void* payload)
{
	NOWPROTO_COMMAND* command = payload;
	IWTSVirtualChannel* transport = command->channel->transport;
	if (!transport)
		return command->close ? CHANNEL_RC_OK : ERROR_NOT_CONNECTED;
	if (command->close)
		return transport->Close(transport);
	return transport->Write(transport, command->size, command->data, nullptr);
}

static void nowproto_command_complete(void* payload, UINT status)
{
	NOWPROTO_COMMAND* command = payload;
	NOWPROTO_CHANNEL* channel = command->channel;
	channel->callbacks.OperationCompleted(channel->callbacks.custom, &channel->endpoint,
	                                      command->token, status);
	nowproto_release(&channel->endpoint);
	free(command);
}

static UINT nowproto_submit(NowProtoEndpoint* endpoint, const BYTE* data, UINT32 size, void* token,
                            BOOL* queued, BOOL close)
{
	if (!queued)
		return ERROR_INVALID_PARAMETER;
	*queued = FALSE;
	if (!close && (!data || !size))
		return ERROR_INVALID_PARAMETER;
	NOWPROTO_CHANNEL* channel = nowproto_channel(endpoint);
	if (InterlockedCompareExchange(&channel->closed, 0, 0))
		return close ? CHANNEL_RC_OK : ERROR_NOT_CONNECTED;
	const size_t allocation = sizeof(NOWPROTO_COMMAND) + (size_t)size;
	if (allocation < (size_t)size)
		return ERROR_INVALID_PARAMETER;
	NOWPROTO_COMMAND* command = malloc(allocation);
	if (!command)
		return ERROR_NOT_ENOUGH_MEMORY;
	command->channel = channel;
	command->token = token;
	command->size = size;
	command->close = close;
	if (size)
		CopyMemory(command->data, data, size);
	nowproto_retain(endpoint);
	const UINT status = freerdp_drdynvc_dispatcher_post(channel->dispatcher, nowproto_command_run,
	                                                    nowproto_command_complete, command);
	if (status == CHANNEL_RC_OK)
		*queued = TRUE;
	else
	{
		nowproto_release(endpoint);
		free(command);
	}
	return status;
}

static UINT nowproto_endpoint_write(NowProtoEndpoint* endpoint, const BYTE* data, UINT32 size,
                                    void* token, BOOL* queued)
{
	return nowproto_submit(endpoint, data, size, token, queued, FALSE);
}

static UINT nowproto_endpoint_close(NowProtoEndpoint* endpoint, void* token, BOOL* queued)
{
	return nowproto_submit(endpoint, nullptr, 0, token, queued, TRUE);
}

static UINT nowproto_write(NowProtoClientContext* context, void* data, int size)
{
	if (!context || (size < 0) || (!data && size))
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
	/* Legacy ABI retains its historical synchronous/raw-channel semantics.
	 * Only V2 submissions have the worker-dispatch lifetime contract. */
	const UINT status = channel->transport->Write(channel->transport, (UINT32)size, data, nullptr);
	nowproto_release(&channel->endpoint);
	return status;
}

UINT freerdp_nowproto_client_set_callbacks(NowProtoClientContext* context,
                                           const NowProtoClientCallbacksV2* callbacks)
{
	if (!context || !callbacks || (callbacks->size != sizeof(*callbacks)) ||
	    (callbacks->version != NOWPROTO_CLIENT_CALLBACKS_VERSION_2) || !callbacks->Offer ||
	    !callbacks->Receive || !callbacks->Closed || !callbacks->OperationCompleted)
		return ERROR_INVALID_PARAMETER;

	NOWPROTO_PLUGIN* plugin = context->handle;
	if (!plugin->dispatcher)
		return ERROR_NOT_SUPPORTED;
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
	nowproto_retain(&channel->endpoint);
	EnterCriticalSection(&plugin->lock);
	plugin->opened = TRUE;
	channel->callbacks = plugin->callbacks;
	channel->offered = channel->callbacks.version != 0;
	LeaveCriticalSection(&plugin->lock);

	if (channel->offered)
		channel->callbacks.Offer(channel->callbacks.custom, &channel->endpoint);
	nowproto_release(&channel->endpoint);
	return CHANNEL_RC_OK;
}

static UINT nowproto_on_data_received(IWTSVirtualChannelCallback* callback, wStream* data)
{
	NOWPROTO_CHANNEL* channel = (NOWPROTO_CHANNEL*)callback;
	UINT status = CHANNEL_RC_OK;
	nowproto_retain(&channel->endpoint);
	if (channel->offered)
		channel->callbacks.Receive(channel->callbacks.custom, &channel->endpoint,
		                           Stream_Pointer(data), Stream_GetRemainingLength(data));
	else
	{
		NowProtoClientContext* context = &channel->plugin->context;
		if (context->Read)
			status = context->Read(context, Stream_Pointer(data), Stream_GetRemainingLength(data));
	}
	nowproto_release(&channel->endpoint);
	return status;
}

static UINT nowproto_on_close(IWTSVirtualChannelCallback* callback)
{
	NOWPROTO_CHANNEL* channel = (NOWPROTO_CHANNEL*)callback;
	NOWPROTO_PLUGIN* plugin = channel->plugin;
	channel->transport = nullptr;
	(void)InterlockedCompareExchange(&channel->closed, 1, 0);
	EnterCriticalSection(&plugin->lock);
	if (plugin->current == channel)
		plugin->current = nullptr;
	LeaveCriticalSection(&plugin->lock);

	if (channel->offered)
		channel->callbacks.Closed(channel->callbacks.custom, &channel->endpoint);
	nowproto_release(&channel->endpoint); /* The native channel callback's reference. */
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
	channel->transport = transport;
	channel->dispatcher = plugin->dispatcher;
	if (channel->dispatcher)
		freerdp_drdynvc_dispatcher_retain(channel->dispatcher);
	channel->iface.OnDataReceived = nowproto_on_data_received;
	channel->iface.OnOpen = nowproto_on_open;
	channel->iface.OnClose = nowproto_on_close;
	channel->endpoint.Retain = nowproto_retain;
	channel->endpoint.Release = nowproto_release;
	channel->endpoint.SubmitWrite = nowproto_endpoint_write;
	channel->endpoint.RequestClose = nowproto_endpoint_close;
	channel->refs = 1;
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
	const UINT acquired = freerdp_drdynvc_dispatcher_acquire(manager, &plugin->dispatcher);
	if ((acquired != CHANNEL_RC_OK) && (acquired != ERROR_NOT_SUPPORTED))
		return acquired;
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
	/* Worker commands and channel callbacks have finished before Terminated. */
	if (plugin->listener)
	{
		const UINT status = plugin->manager->DestroyListener(plugin->manager, plugin->listener);
		if (status != CHANNEL_RC_OK)
			WLog_ERR(TAG, "DestroyListener failed: %" PRIu32, status);
	}
	freerdp_drdynvc_dispatcher_release(plugin->dispatcher);
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
