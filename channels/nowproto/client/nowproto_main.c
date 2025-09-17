#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/print.h>
#include <winpr/stream.h>
#include <winpr/cmdline.h>
#include <winpr/collections.h>

#include <freerdp/addin.h>
#include <freerdp/client/channels.h>
#include <freerdp/channels/log.h>

#define TAG CHANNELS_TAG("nowproto.client")

#include "nowproto_main.h"

typedef struct
{
	GENERIC_DYNVC_PLUGIN base;
	NowProtoClientContext* context;
} NOWPROTO_PLUGIN;

static UINT nowproto_write(NowProtoClientContext* context, void* data, int size)
{
	NOWPROTO_PLUGIN* nowproto = NULL;
	GENERIC_CHANNEL_CALLBACK* callback = NULL;
	wStream* s;
	UINT status;
	
	WINPR_ASSERT(context);
	nowproto = (NOWPROTO_PLUGIN*) context->handle;
	WINPR_ASSERT(nowproto);
	
	s = Stream_New(NULL, size);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return CHANNEL_RC_NO_MEMORY;
	}
	
	Stream_Write(s, (void*) data, size);
	Stream_SealLength(s);

	callback = nowproto->base.listener_callback->channel_callback;
	status = callback->channel->Write(callback->channel, (UINT32) Stream_Length(s), Stream_Buffer(s), NULL);
	
	Stream_Free(s, TRUE);
	
	if (status != CHANNEL_RC_OK)
	{
		WLog_ERR(TAG, "nowproto_write failed with %s [%08"PRIX32"]", WTSErrorToString(status), status);
	}

	return status;
}

static UINT nowproto_on_data_received(IWTSVirtualChannelCallback* pChannelCallback, wStream* data)
{
	GENERIC_CHANNEL_CALLBACK* callback = (GENERIC_CHANNEL_CALLBACK*) pChannelCallback;
	NOWPROTO_PLUGIN* nowproto = NULL;
	NowProtoClientContext* context = NULL;
	UINT ret = CHANNEL_RC_OK;
	
	WINPR_ASSERT(callback);
	WINPR_ASSERT(data);
	
	nowproto = (NOWPROTO_PLUGIN*) callback->plugin;
	WINPR_ASSERT(nowproto);
	
	context = nowproto->context;
	WINPR_ASSERT(context);
	
	if (context->Read)
	{
		ret = context->Read(context, Stream_Pointer(data), Stream_GetRemainingLength(data));
	}
	
	return ret;
}

static UINT nowproto_on_close(IWTSVirtualChannelCallback* pChannelCallback)
{
	free(pChannelCallback);
	return CHANNEL_RC_OK;
}

/**
 * Channel Client Interface
 */

static const IWTSVirtualChannelCallback nowproto_callbacks = { nowproto_on_data_received,
	                                                           NULL, /* Open */
	                                                           nowproto_on_close, NULL };

static UINT init_plugin_cb(GENERIC_DYNVC_PLUGIN* base, WINPR_ATTR_UNUSED rdpContext* rcontext, rdpSettings* settings)
{
	NowProtoClientContext* context = NULL;
	NOWPROTO_PLUGIN* nowproto = (NOWPROTO_PLUGIN*) base;

	WINPR_ASSERT(nowproto);
	WINPR_UNUSED(settings);

	 context = (NowProtoClientContext*) calloc(1, sizeof(NowProtoClientContext));
	
	 if (!context)
	 {
	 	WLog_Print(base->log, WLOG_ERROR, "calloc failed!");
	 	return CHANNEL_RC_NO_MEMORY;
	 }

	context->handle = (void*) nowproto;
	context->Write = nowproto_write;

	nowproto->context = context;
	nowproto->base.iface.pInterface = (void*) context;
	
	return CHANNEL_RC_OK;
}

static void terminate_plugin_cb(GENERIC_DYNVC_PLUGIN* base)
{
	NOWPROTO_PLUGIN* nowproto = (NOWPROTO_PLUGIN*) base;

	free(nowproto->context);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
FREERDP_ENTRY_POINT(UINT VCAPITYPE nowproto_DVCPluginEntry(IDRDYNVC_ENTRY_POINTS* pEntryPoints))
{
	return freerdp_generic_DVCPluginEntry(pEntryPoints, TAG, NOWPROTO_DVC_CHANNEL_NAME,
	                                      sizeof(NOWPROTO_PLUGIN), sizeof(GENERIC_CHANNEL_CALLBACK),
	                                      &nowproto_callbacks, init_plugin_cb, terminate_plugin_cb);
}
