#include <freerdp/channels/channels.h>
#include <freerdp/client/channels.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/event.h>
#include <freerdp/settings.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/gdi/gfx.h>
#include <freerdp/utils/signal.h>
#include <assert.h>
#include <ctype.h>
#include <freerdp/log.h>
#include <winpr/environment.h>
#include <winpr/string.h>
#include <winpr/sysinfo.h>

#include "DevolutionsRdp.h"
#include "clipboard.h"
#include "cursor.h"
#include "virtualchannel.h"

#define TAG "DevolutionsRdp"

#ifndef _WIN32
// Credentials module was removed from winpr
#define CRED_MAX_USERNAME_LENGTH (256 + 1 + 256)
#define CRED_MAX_DOMAIN_TARGET_NAME_LENGTH (256 + 1 + 80)
#define CRED_MAX_CREDENTIAL_BLOB_SIZE 512
#endif

#define RESIZE_MIN_DELAY 200 /* minimum delay in ms between two resizes */

static BOOL cs_pre_connect(freerdp* instance);
static BOOL cs_post_connect(freerdp* instance);
static void cs_post_disconnect(freerdp* instance);
static BOOL cs_authenticate(freerdp* instance, char** username, char** password, char** domain, rdp_auth_reason reason);
static DWORD cs_verify_certificate(freerdp* instance, const char* host, UINT16 port,
                                   const char* common_name, const char* subject, const char* issuer,
                                   const char* fingerprint, DWORD flags);
static int cs_verify_x509_certificate(freerdp* instance, const BYTE* data, size_t length, const char* hostname, uint16_t port, DWORD flags);
static char** freerdp_command_line_parse_comma_separated_values_offset(const char* name, char* list, size_t* count);
static char** freerdp_command_line_parse_comma_separated_values_ex(const char* name, const char* list, size_t* count);
void cs_error_info(void* ctx, const ErrorInfoEventArgs* e);
BOOL cs_client_global_init(void);

static int cs_get_vk_code(int character)
{
	int _virtual_key_map[256] = {0};
	
	_virtual_key_map['0'] = VK_KEY_0;
	_virtual_key_map['1'] = VK_KEY_1;
	_virtual_key_map['2'] = VK_KEY_2;
	_virtual_key_map['3'] = VK_KEY_3;
	_virtual_key_map['4'] = VK_KEY_4;
	_virtual_key_map['5'] = VK_KEY_5;
	_virtual_key_map['6'] = VK_KEY_6;
	_virtual_key_map['7'] = VK_KEY_7;
	_virtual_key_map['8'] = VK_KEY_8;
	_virtual_key_map['9'] = VK_KEY_9;
	
	_virtual_key_map['a'] = VK_KEY_A;
	_virtual_key_map['b'] = VK_KEY_B;
	_virtual_key_map['c'] = VK_KEY_C;
	_virtual_key_map['d'] = VK_KEY_D;
	_virtual_key_map['e'] = VK_KEY_E;
	_virtual_key_map['f'] = VK_KEY_F;
	_virtual_key_map['g'] = VK_KEY_G;
	_virtual_key_map['h'] = VK_KEY_H;
	_virtual_key_map['i'] = VK_KEY_I;
	_virtual_key_map['j'] = VK_KEY_J;
	_virtual_key_map['k'] = VK_KEY_K;
	_virtual_key_map['l'] = VK_KEY_L;
	_virtual_key_map['m'] = VK_KEY_M;
	_virtual_key_map['n'] = VK_KEY_N;
	_virtual_key_map['o'] = VK_KEY_O;
	_virtual_key_map['p'] = VK_KEY_P;
	_virtual_key_map['q'] = VK_KEY_Q;
	_virtual_key_map['r'] = VK_KEY_R;
	_virtual_key_map['s'] = VK_KEY_S;
	_virtual_key_map['t'] = VK_KEY_T;
	_virtual_key_map['u'] = VK_KEY_U;
	_virtual_key_map['v'] = VK_KEY_V;
	_virtual_key_map['w'] = VK_KEY_W;
	_virtual_key_map['x'] = VK_KEY_X;
	_virtual_key_map['y'] = VK_KEY_Y;
	_virtual_key_map['z'] = VK_KEY_Z;
	
	return _virtual_key_map[character];
}

static int cs_get_unicode(int character)
{
	int _unicode_map[256] = {0};
	
	_unicode_map['-'] = 45;
	_unicode_map['/'] = 47;
	_unicode_map[':'] = 58;
	_unicode_map[';'] = 59;
	_unicode_map['('] = 40;
	_unicode_map[')'] = 41;
	_unicode_map['&'] = 38;
	_unicode_map['@'] = 64;
	_unicode_map['.'] = 46;
	_unicode_map[','] = 44;
	_unicode_map['?'] = 63;
	_unicode_map['!'] = 33;
	_unicode_map['\''] = 39;
	_unicode_map['\"'] = 34;
	
	_unicode_map['['] = 91;
	_unicode_map[']'] = 93;
	_unicode_map['{'] = 123;
	_unicode_map['}'] = 125;
	_unicode_map['#'] = 35;
	_unicode_map['%'] = 37;
	_unicode_map['^'] = 94;
	_unicode_map['*'] = 42;
	_unicode_map['+'] = 43;
	_unicode_map['='] = 61;
	
	_unicode_map['_'] = 95;
	_unicode_map['\\'] = 92;
	_unicode_map['|'] = 124;
	_unicode_map['~'] = 126;
	_unicode_map['<'] = 60;
	_unicode_map['>'] = 62;
	_unicode_map['$'] = 36;
	
	return _unicode_map[character];
}

int cs_vrtchn_init(csContext* ctx, VirtChanContext* virtchan)
{
	char* channelName = cs_channel_get_name(virtchan);

	if(strcmp(channelName, "RDMJump") == 0)
	{
		ctx->rdpjump = virtchan;
	}
	else if(strcmp(channelName, "RDMCmd") == 0)
	{
		ctx->rdpcmd = virtchan;
	}
	else if(strcmp(channelName, "RDMLog") == 0)
	{
		ctx->rdplog = virtchan;
	}
	else
	{
		return 0;
	}

	cs_channel_set_on_received_data(virtchan, ctx->onChannelReceivedData);
	virtchan->custom = (void*) ctx->_p.instance;
	return 1;
}

int cs_vrtchn_uninit(csContext* ctx, VirtChanContext* virtchan)
{
	char* channelName = cs_channel_get_name(virtchan);
	
	if(strcmp(channelName, "RDMJump") == 0)
	{
		ctx->rdpjump = NULL;
	}
	else if(strcmp(channelName, "RDMCmd") == 0)
	{
		ctx->rdpcmd = NULL;
	}
	else if(strcmp(channelName, "RDMLog") == 0)
	{
		ctx->rdplog = NULL;
	}

	virtchan->custom = NULL;

	return 1;
}

static void cs_send_virtual_key(freerdp* instance, int vk, BOOL down)
{
	int flags;
	DWORD scancode;
	
	scancode = GetVirtualScanCodeFromVirtualKeyCode(vk, 4);
	flags = (down ? KBD_FLAGS_DOWN : KBD_FLAGS_RELEASE);
	flags |= ((scancode & KBDEXT) ? KBD_FLAGS_EXTENDED : 0);
	freerdp_input_send_keyboard_event(instance->input, flags, scancode & 0xFF);
}

static void cs_send_unicode_key(freerdp* instance, int vk)
{
	freerdp_input_send_unicode_keyboard_event(instance->input, 0, vk);
}

void cs_OnChannelConnectedEventHandler(rdpContext* context, ChannelConnectedEventArgs* e)
{
	csContext* csc = (csContext*)context->instance->context;

	if (csc->channelConnected && csc->channelConnected(context, e->name, e->pInterface))
	{
		return;
	}
	else if (strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME) == 0)
	{
		gdi_graphics_pipeline_init(context->gdi, (RdpgfxClientContext*) e->pInterface);
	}
	else if (strcmp(e->name, CLIPRDR_SVC_CHANNEL_NAME) == 0)
	{
		cs_cliprdr_init(csc, (CliprdrClientContext*) e->pInterface);
	}
	else if (strcmp(e->name, DISP_DVC_CHANNEL_NAME) == 0)
	{
		csc->disp = (DispClientContext*)e->pInterface;
	}
	else if(strncmp(e->name, "RDM", 3) == 0)
	{
		cs_vrtchn_init(csc, (VirtChanContext*) e->pInterface);
	}
}

void cs_OnChannelDisconnectedEventHandler(rdpContext* context, ChannelDisconnectedEventArgs* e)
{
	csContext* csc = (csContext*)context->instance->context;

	if (csc->channelDisconnected && csc->channelDisconnected(context, e->name, e->pInterface))
	{
		return;
	}
	if (strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME) == 0)
	{
		gdi_graphics_pipeline_uninit(context->gdi, (RdpgfxClientContext*) e->pInterface);
	}
	else if (strcmp(e->name, CLIPRDR_SVC_CHANNEL_NAME) == 0)
	{
		cs_cliprdr_uninit(csc, (CliprdrClientContext*) e->pInterface);
	}
	else if (strcmp(e->name, DISP_DVC_CHANNEL_NAME) == 0)
	{
		csc->disp = NULL;
	}
	else if(strncmp(e->name, "RDM", 3) == 0)
	{
		cs_vrtchn_uninit(csc, (VirtChanContext*) e->pInterface);
	}
}

static BOOL cs_context_new(freerdp* instance, rdpContext* context)
{
	rdpSettings* settings = instance->settings;

	instance->PreConnect = cs_pre_connect;
	instance->PostConnect = cs_post_connect;
	instance->PostDisconnect = cs_post_disconnect;
	instance->AuthenticateEx = cs_authenticate;
	instance->VerifyCertificateEx = cs_verify_certificate;
	instance->VerifyX509Certificate = cs_verify_x509_certificate;

	PubSub_SubscribeErrorInfo(context->pubSub, cs_error_info);

	settings->AsyncUpdate = FALSE;

	return TRUE;
}

static void cs_context_free(freerdp* instance, rdpContext* context)
{

}

static BOOL cs_pre_connect(freerdp* instance)
{
	rdpContext* context = instance->context;
	rdpSettings* settings = instance->settings;
	BOOL bitmap_cache = settings->BitmapCacheEnabled;
	
	ZeroMemory(settings->OrderSupport, 32);
	settings->OrderSupport[NEG_DSTBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_PATBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_SCRBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_OPAQUE_RECT_INDEX] = TRUE;
	settings->OrderSupport[NEG_DRAWNINEGRID_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIDSTBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIPATBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTISCRBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIOPAQUERECT_INDEX] = TRUE;
	settings->OrderSupport[NEG_MULTI_DRAWNINEGRID_INDEX] = FALSE;
	settings->OrderSupport[NEG_LINETO_INDEX] = TRUE;
	settings->OrderSupport[NEG_POLYLINE_INDEX] = TRUE;
	settings->OrderSupport[NEG_MEMBLT_INDEX] = bitmap_cache;
	settings->OrderSupport[NEG_MEM3BLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_MEMBLT_V2_INDEX] = bitmap_cache;
	settings->OrderSupport[NEG_MEM3BLT_V2_INDEX] = FALSE;
	settings->OrderSupport[NEG_SAVEBITMAP_INDEX] = FALSE;
	settings->OrderSupport[NEG_GLYPH_INDEX_INDEX] = TRUE;
	settings->OrderSupport[NEG_FAST_INDEX_INDEX] = TRUE;
	settings->OrderSupport[NEG_FAST_GLYPH_INDEX] = TRUE;
	settings->OrderSupport[NEG_POLYGON_SC_INDEX] = FALSE;
	settings->OrderSupport[NEG_POLYGON_CB_INDEX] = FALSE;
	settings->OrderSupport[NEG_ELLIPSE_SC_INDEX] = FALSE;
	settings->OrderSupport[NEG_ELLIPSE_CB_INDEX] = FALSE;

	if (!freerdp_client_load_addins(context->channels, instance->settings))
			return -1;

	PubSub_SubscribeChannelConnected(context->pubSub,
									 (pChannelConnectedEventHandler) cs_OnChannelConnectedEventHandler);

	PubSub_SubscribeChannelDisconnected(context->pubSub,
										(pChannelDisconnectedEventHandler) cs_OnChannelDisconnectedEventHandler);

	if (!context->cache)
	{
		if (!(context->cache = cache_new(context)))
			return FALSE;
	}

	return TRUE;
}

BOOL cs_begin_paint(rdpContext* context)
{
	rdpGdi* gdi = context->gdi;
	
	gdi->primary->hdc->hwnd->invalid->null = 1;
	return TRUE;
}

BOOL cs_end_paint(rdpContext* context)
{
	rdpGdi* gdi = context->gdi;
	csContext* csc = (csContext*)context->instance->context;
	INT32 x, y;
	UINT32 w, h;
	
	if (gdi->primary->hdc->hwnd->invalid->null)
		return TRUE;

	x = gdi->primary->hdc->hwnd->invalid->x;
	y = gdi->primary->hdc->hwnd->invalid->y;
	w = gdi->primary->hdc->hwnd->invalid->w;
	h = gdi->primary->hdc->hwnd->invalid->h;

	if (csc->regionUpdated)
		csc->regionUpdated(context->instance, x, y, w, h);

	gdi->primary->hdc->hwnd->ninvalid = 0;

	return TRUE;
}

BOOL cs_desktop_resize(rdpContext* context)
{
	int stride;
	rdpGdi* gdi;
	rdpSettings* settings;
	csContext* csc;

	if (!context || !context->settings)
		return FALSE;

	gdi = context->gdi;
	settings = context->settings;
	csc = (csContext*)context->instance->context;

	stride = settings->DesktopWidth * 4;

	if (!csc->desktopSizeChanged)
		return FALSE;

	csc->buffer = csc->desktopSizeChanged(context->instance, settings->DesktopWidth, settings->DesktopHeight);

	if(!csc->buffer)
		return FALSE;

	if (!gdi_resize_ex(gdi, settings->DesktopWidth, settings->DesktopHeight,
					stride, PIXEL_FORMAT_BGRX32, csc->buffer, NULL))
	{
		return FALSE;
	}

	return TRUE;
}

void freerdp_csharp_input_cb(freerdp *instance)
{
	int status;
	wMessage message;
	wMessageQueue *queue;
	status = 1;
	queue = freerdp_get_message_queue(instance, FREERDP_INPUT_MESSAGE_QUEUE);

	if (queue)
	{
		while (MessageQueue_Peek(queue, &message, TRUE))
		{
			status = freerdp_message_queue_process_message(instance, 
					 FREERDP_INPUT_MESSAGE_QUEUE, &message);

			if (!status)
				break;
		}
	}
	else
	{
		WLog_ERR(TAG, "freerdp_csharp_input_cb: No queue!");
	}
}

static BOOL cs_post_connect(freerdp* instance)
{
	UINT32 stride;
	rdpUpdate* update;
	csContext* context = (csContext*)instance->context;
	rdpSettings* settings = instance->settings;

	update = instance->context->update;
	
	assert(instance);

	stride = settings->DesktopWidth * 4;
	settings->GfxH264 = FALSE;

	if (!gdi_init_ex(instance, PIXEL_FORMAT_BGRX32, stride, context->buffer, NULL))
		return FALSE;

	update->BeginPaint = cs_begin_paint;
	update->EndPaint = cs_end_paint;
	update->DesktopResize = cs_desktop_resize;
	
	pointer_cache_register_callbacks(update);
	cs_register_pointer((rdpContext*)context);

	return TRUE;
}

static void cs_post_disconnect(freerdp* instance)
{   
	gdi_free(instance);
}

static BOOL cs_do_authenticate(freerdp* instance, char** username, char** password, char** domain, rdp_auth_reason reason)
{
	csContext* context = (csContext*)instance->context;
	BOOL result = TRUE;
	fnOnAuthenticate callback = context->onAuthenticate;

	if (reason > AUTH_RDP)
	{
		callback = context->onGwAuthenticate;
		result = FALSE;
	}

	if (!callback)
	{
		goto out;
	}

	char pszUsername[CRED_MAX_USERNAME_LENGTH + 1];
	char pszPassword[(CRED_MAX_CREDENTIAL_BLOB_SIZE / 2) + 1];
	char pszDomain[CRED_MAX_DOMAIN_TARGET_NAME_LENGTH + 1];

	ZeroMemory(pszUsername, sizeof(pszUsername));

	if (*username)
		strncpy(pszUsername, *username, sizeof(pszUsername) - 1);

	ZeroMemory(pszPassword, sizeof(pszPassword));
		
	if (*password)
		strncpy(pszPassword, *password, sizeof(pszPassword) - 1);

	ZeroMemory(pszDomain, sizeof(pszDomain));
		
	if (*domain)
		strncpy(pszDomain, *domain, sizeof(pszDomain) - 1);
		
	result = callback(instance, 
		pszUsername, (int)sizeof(pszUsername), 
		pszPassword, (int)sizeof(pszPassword), 
		pszDomain, (int)sizeof(pszDomain),
		reason);
		
	if (result)
	{
		free(*username);
		*username = _strdup(pszUsername);

		free(*password);
		*password = _strdup(pszPassword);
			
		free(*domain);
		*domain = _strdup(pszDomain);
	}

out:
	return result;
}

static BOOL cs_authenticate(freerdp* instance, char** username, char** password, char** domain, rdp_auth_reason reason)
{
	csContext* context = (csContext*)instance->context;
	return cs_do_authenticate(instance, username, password, domain, reason);
}

static DWORD cs_verify_certificate(freerdp* instance, const char* host, UINT16 port,
	const char* common_name, const char* subject, 
	const char* issuer, const char* fingerprint, DWORD flags)
{
	return TRUE;
}

static int cs_verify_x509_certificate(freerdp* instance, const BYTE* data, size_t length, const char* hostname, uint16_t port, DWORD flags)
{
	return 1;
}

void cs_error_info(void* ctx, const ErrorInfoEventArgs* e)
{
	rdpContext* context = (rdpContext*) ctx;
	csContext* csc = (csContext*)context->instance->context;
	
	if (csc->onError)
	{
		csc->onError(context->instance, e->code);
	}
}

BOOL csharp_configure_log_callback(int wlogLevel, wLogCallbackMessage_t fn)
{
	wLog* root;
	wLogAppender* appender;
	wLogCallbacks callbacks;

	ZeroMemory((void*) &callbacks, sizeof(wLogCallbacks));
	callbacks.message = fn;

	if (wlogLevel > WLOG_OFF)
		wlogLevel = WLOG_OFF;

	root = WLog_GetRoot();

	WLog_SetLogLevel(root, wlogLevel);
	WLog_SetLogAppenderType(root, WLOG_APPENDER_CALLBACK);

	appender = WLog_GetLogAppender(root);

	if (!WLog_ConfigureAppender(appender, "callbacks", (void*) &callbacks))
		return FALSE;

	return TRUE;
}

BOOL csharp_configure_log_file(int wlogLevel, const char* logPath, const char* logName)
{
	wLog* root;
	wLogAppender* appender;

	if (wlogLevel > WLOG_OFF)
		wlogLevel = WLOG_OFF;

	root = WLog_GetRoot();

	WLog_SetLogLevel(root, wlogLevel);
	WLog_SetLogAppenderType(root, WLOG_APPENDER_FILE);

	appender = WLog_GetLogAppender(root);

	if (!WLog_ConfigureAppender(appender, "outputfilename", (void*) logName))
		return FALSE;

	if (!WLog_ConfigureAppender(appender, "outputfilepath", (void*) logPath))
		return FALSE;

	return TRUE;
}

BOOL cs_client_global_init(void)
{
	BOOL result = TRUE;

#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		result = FALSE;
	}
#endif

	return result;
}

void csharp_freerdp_client_global_uninit(void)
{
#ifdef WIN32
	WSACleanup();
#endif
}

int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints)
{
	pEntryPoints->Version = RDP_CLIENT_INTERFACE_VERSION;
	pEntryPoints->Size = sizeof(RDP_CLIENT_ENTRY_POINTS);

	pEntryPoints->GlobalInit = cs_client_global_init;
	pEntryPoints->GlobalUninit = csharp_freerdp_client_global_uninit;

	pEntryPoints->ContextSize = sizeof(csContext);
	pEntryPoints->ClientNew = cs_context_new;
	pEntryPoints->ClientFree = cs_context_free;

	return 0;
}

static char** freerdp_command_line_parse_comma_separated_values_offset(
	const char* name, char* list, size_t* count)
{
	return freerdp_command_line_parse_comma_separated_values_ex(name, list, count);
}

static char** freerdp_command_line_parse_comma_separated_values_ex(const char* name,
		const char* list, size_t* count)
{
	char** p;
	char* str;
	size_t nArgs;
	size_t index;
	size_t nCommas;
	size_t prefix, len;
	nCommas = 0;
	assert(NULL != count);
	*count = 0;

	if (!list)
	{
		if (name)
		{
			size_t len = strlen(name);
			p = (char**) calloc(2UL + len, sizeof(char*));

			if (p)
			{
				char* dst = (char*)&p[1];
				p[0] = dst;
				sprintf_s(dst, len + 1, "%s", name);
				*count = 1;
				return p;
			}
		}

		return NULL;
	}

	{
		const char* it = list;

		while ((it = strchr(it, ',')) != NULL)
		{
			it++;
			nCommas++;
		}
	}

	nArgs = nCommas + 1;

	if (name)
		nArgs++;

	prefix = (nArgs + 1UL) * sizeof(char*);
	len = strlen(list);
	p = (char**) calloc(len + prefix + 1, sizeof(char*));

	if (!p)
		return NULL;

	str = &((char*)p)[prefix];
	memcpy(str, list, len);

	if (name)
		p[0] = (char*)name;

	for (index = name ? 1 : 0; index < nArgs; index++)
	{
		char* comma = strchr(str, ',');
		p[index] = str;

		if (comma)
		{
			str = comma + 1;
			*comma = '\0';
		}
	}

	*count = nArgs;
	return p;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////
//// EXPORTED FUNCTIONS
////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void* csharp_freerdp_new()
{
	void* context;
	RDP_CLIENT_ENTRY_POINTS clientEntryPoints;
	
	ZeroMemory(&clientEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
	clientEntryPoints.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
	
	RdpClientEntry(&clientEntryPoints);
	
	context = freerdp_client_context_new(&clientEntryPoints)->instance;
	freerdp_register_addin_provider(cs_channels_load_static_addin_entry, 0);
	
	return context;
}

void csharp_freerdp_free(void* instance)
{
	freerdp* inst = (freerdp*)instance;

	freerdp_client_context_free(inst->context);
}

BOOL csharp_freerdp_connect(void* instance)
{
	return freerdp_connect((freerdp*)instance);
}

BOOL csharp_freerdp_disconnect(void* instance)
{
	freerdp* inst = (freerdp*)instance;

	return freerdp_disconnect(inst);
}

BOOL csharp_freerdp_abort_connect(void* instance)
{
	freerdp* inst = (freerdp*)instance;

	return freerdp_abort_connect(inst);
}

void csharp_freerdp_set_initial_buffer(void* instance, void* buffer)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;

	ctxt->buffer = buffer;
}

void csharp_freerdp_set_on_channel_connected(void* instance, fnChannelConnected fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* csc = (csContext*)inst->context;
	
	csc->channelConnected = fn;
}

void csharp_freerdp_set_on_channel_disconnected(void* instance, fnChannelDisconnected fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* csc = (csContext*)inst->context;
	
	csc->channelDisconnected = fn;
}

void csharp_freerdp_set_on_region_updated(void* instance, fnRegionUpdated fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;
	
	ctxt->regionUpdated = fn;
}

void csharp_freerdp_set_on_desktop_size_changed(void* instance, fnDesktopSizeChanged fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;
	
	ctxt->desktopSizeChanged = fn;
}

BOOL csharp_freerdp_set_gateway_settings(void* instance, const char* hostname, UINT32 port, const char* username, const char* password, const char* domain, BOOL bypassLocal, BOOL httpTransport, BOOL rpcTransport)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->GatewayPort = port;
	settings->GatewayEnabled = TRUE;
	settings->GatewayUseSameCredentials = FALSE;
	settings->GatewayHostname = _strdup(hostname);
	settings->GatewayUsername = _strdup(username);
	settings->GatewayPassword = _strdup(password);
	settings->GatewayDomain = _strdup(domain);
	settings->GatewayBypassLocal = bypassLocal;
	settings->GatewayHttpTransport = httpTransport;
	settings->GatewayRpcTransport = rpcTransport;
	settings->CredentialsFromStdin = FALSE;

	freerdp_update_gateway_usage_method(settings, TRUE, bypassLocal);
	
	if (!settings->GatewayHostname || !settings->GatewayUsername ||
		!settings->GatewayPassword || !settings->GatewayDomain)
	{
		return FALSE;
	}
	
	return TRUE;
}

BOOL csharp_freerdp_set_client_hostname(void* instance, const char* clientHostname)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	if (!(settings->ClientHostname = _strdup(clientHostname)))
		return FALSE;

	return TRUE;
}

void csharp_freerdp_set_console_mode(void* instance, BOOL useConsoleMode, BOOL useRestrictedAdminMode)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->ConsoleSession = useConsoleMode;
	settings->RestrictedAdminModeRequired = useRestrictedAdminMode;
}

void csharp_freerdp_set_redirect_clipboard(void* instance, BOOL redirectClipboard)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->RedirectClipboard = redirectClipboard;
}

void csharp_freerdp_set_redirect_audio(void* instance, int redirectSound, BOOL redirectCapture)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	char** p;
	size_t count;

	if (redirectSound == AUDIO_MODE_REDIRECT)
	{
		settings->AudioPlayback = TRUE;
		p = freerdp_command_line_parse_comma_separated_values_offset("rdpsnd", NULL, &count);
		freerdp_client_add_static_channel(settings, count, p);
		free(p);
	}
	else if (redirectSound == AUDIO_MODE_PLAY_ON_SERVER)
	{
		settings->RemoteConsoleAudio = TRUE;
	}
	else if (redirectSound == AUDIO_MODE_NONE)
	{
		settings->AudioPlayback = FALSE;
		settings->RemoteConsoleAudio = FALSE;
	}

	if (redirectCapture)
	{
		p = freerdp_command_line_parse_comma_separated_values_offset("audin", NULL, &count);
		freerdp_client_add_dynamic_channel(settings, count, p);
		free(p);
	}
}

BOOL csharp_freerdp_set_connection_info(void* instance, const char* hostname, const char* username, const char* password, const char* domain, UINT32 width, UINT32 height, UINT32 color_depth, UINT32 port, int codecLevel)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->DesktopWidth = width;
	settings->DesktopHeight = height;
	settings->ColorDepth = color_depth;
	settings->ServerPort = port;
	settings->ExternalCertificateManagement = TRUE;

	// Hack for 16 bit RDVH connections:
	//   In this case we get screen corruptions when we have an odd screen resolution width ... need to investigate what is causing this...
	if (color_depth <= 16)
		settings->DesktopWidth &= (~1);

	if (!(settings->ServerHostname = _strdup(hostname)))
		goto out_fail_strdup;

	if (username && strlen(username) > 0)
	{
		if (!(settings->Username = _strdup(username)))
			goto out_fail_strdup;
	}

	if (password && strlen(password) > 0)
	{
		if (!(settings->Password = _strdup(password)))
			goto out_fail_strdup;

		settings->AutoLogonEnabled = TRUE;
	}

	if (!(settings->Domain = _strdup(domain)))
		goto out_fail_strdup;

	settings->SoftwareGdi = TRUE;
	settings->AllowFontSmoothing = TRUE;
	
	if (codecLevel >= 7)
	{
		settings->RemoteFxCodec = TRUE;
		settings->FastPathOutput = TRUE;
		settings->LargePointerFlag = TRUE;
		settings->FrameMarkerCommandEnabled = TRUE;
		settings->ColorDepth = 32;
	}
	
	if(codecLevel >= 8)
	{
		settings->SupportGraphicsPipeline = TRUE;
	}

	// set US keyboard layout
	settings->KeyboardLayout = 0x0409;

	return TRUE;

out_fail_strdup:
	return FALSE;
}

void csharp_freerdp_set_security_info(void* instance, BOOL useTLS, BOOL useNLA)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->RdpSecurity = TRUE;
	settings->TlsSecurity = FALSE;
	settings->NlaSecurity = FALSE;

	if(useTLS)
		settings->TlsSecurity = TRUE;

	if(useNLA)
		settings->NlaSecurity = TRUE;
}

void csharp_freerdp_set_hyperv_info(void* instance, char* pcb)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->PreconnectionBlob = _strdup(pcb);
	settings->VmConnectMode = TRUE;
	settings->SendPreconnectionPdu = TRUE;
	settings->NlaSecurity = TRUE;
	settings->NegotiateSecurityLayer = FALSE;
}

void csharp_freerdp_set_keyboard_layout(void* instance, int layoutID)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->KeyboardLayout = layoutID;
}

void csharp_freerdp_set_redirect_all_drives(void* instance, BOOL redirect)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->RedirectDrives = redirect;
}

void csharp_freerdp_set_redirect_home_drive(void* instance, BOOL redirect)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->RedirectHomeDrive = redirect;
}

void csharp_freerdp_set_redirect_printers(void* instance, BOOL redirect)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->RedirectPrinters = redirect;
}

void csharp_freerdp_set_redirect_smartcards(void* instance, BOOL redirect)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->RedirectSmartCards = redirect;
}

BOOL csharp_freerdp_set_data_directory(void* instance, const char* directory)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->HomePath = settings->ConfigPath = NULL;

	int config_dir_len = (int) strlen(directory) + 10; /* +9 chars for /.freerdp and +1 for \0 */
	char* config_dir_buf = (char*)malloc(config_dir_len);
	if (!config_dir_buf)
		goto out_malloc_fail;

	strcpy(config_dir_buf, directory);
	strcat(config_dir_buf, "/.freerdp");
	settings->HomePath = _strdup(directory);
	if (!settings->HomePath)
		goto out_strdup_fail;
	settings->ConfigPath = config_dir_buf;	/* will be freed by freerdp library */

	return TRUE;

out_strdup_fail:
	free(config_dir_buf);
out_malloc_fail:
	return FALSE;
}

void csharp_freerdp_set_support_display_control(void* instance, BOOL supportDisplayControl)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->SupportDisplayControl = supportDisplayControl;
}

BOOL csharp_freerdp_set_dynamic_resolution_update(void* instance, BOOL dynamicResolutionUpdate)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	if (settings->SmartSizing && dynamicResolutionUpdate) /* Smart sizing and dynamic resolution are mutually exclusing */
		return FALSE;

	settings->DynamicResolutionUpdate = dynamicResolutionUpdate;

	return TRUE;
}

void csharp_freerdp_set_alternate_shell(void* instance, const char* shell)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->AlternateShell = _strdup(shell);
}

void csharp_freerdp_set_shell_working_directory(void* instance, const char* directory)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->ShellWorkingDirectory = _strdup(directory);
}

void csharp_freerdp_set_scale_factor(void* instance, UINT32 desktopScaleFactor, UINT32 deviceScaleFactor)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->DesktopScaleFactor = desktopScaleFactor;
	settings->DeviceScaleFactor = deviceScaleFactor;
}

BOOL csharp_shall_disconnect(void* instance)
{
	return freerdp_shall_disconnect((freerdp*)instance);
}

BOOL csharp_waitforsingleobject(void* instance)
{
	freerdp* inst = (freerdp*)instance;
	HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
	HANDLE inputEvent;
	DWORD nCount = 0;
	DWORD status;

	if (!(inputEvent = freerdp_get_message_queue_event_handle(instance, FREERDP_INPUT_MESSAGE_QUEUE)))
	{
		WLog_ERR(TAG, "freerdp_get_message_queue_event_handle failed");
		return FALSE;
	}

	handles[nCount++] = inputEvent;

	nCount = freerdp_get_event_handles(inst->context, &handles[nCount], ARRAYSIZE(handles) - nCount);

	if (nCount == 0)
	{
		WLog_ERR(TAG, "freerdp_get_event_handles failed");
		return FALSE;
	}

	status = WaitForMultipleObjects(nCount, handles, FALSE, 100);

	if (status == WAIT_FAILED)
		return FALSE;

	if (WaitForSingleObject(inputEvent, 0) == WAIT_OBJECT_0)
	{
		freerdp_csharp_input_cb(instance);
	}

	return TRUE;
}

BOOL csharp_check_event_handles(void* instance, void* buffer)
{
	int result;
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;

	ctxt->buffer = buffer;
	
	result = freerdp_check_event_handles(inst->context);
	
	return result;
}

void csharp_freerdp_send_unicode(void* instance, int character)
{
	cs_send_unicode_key((freerdp*)instance, character);
}

void csharp_freerdp_send_vkcode(void* instance, int vkcode, BOOL down)
{
	cs_send_virtual_key((freerdp*)instance, vkcode, down);
}

void csharp_freerdp_send_input(void* instance, int character, BOOL down)
{
	BOOL shift_was_sent = FALSE;
	
	// Send as is.
	if(character >= 256)
	{
		cs_send_virtual_key((freerdp*)instance, character, down);
		return;
	}
	
	int vk = cs_get_unicode(character);

	if(vk != 0)
	{
		cs_send_unicode_key((freerdp*)instance, vk);
	}
	else
	{
		if(isupper(character))
		{
			character = tolower(character);

			if(down)
				cs_send_virtual_key((freerdp*)instance, VK_LSHIFT, TRUE);

			shift_was_sent = TRUE;
		}
		
		vk = cs_get_vk_code(character);

		if(vk == 0)
		{
			// send as is
			vk = character;
		}
		
		// send key pressed
		cs_send_virtual_key((freerdp*)instance, vk, down);
		
		if(shift_was_sent && !down)
			cs_send_virtual_key((freerdp*)instance, VK_LSHIFT, FALSE);
	}
}

BOOL csharp_freerdp_send_monitor_layout(void* instance, uint32_t targetWidth, uint32_t targetHeight)
{
	BOOL status = FALSE;
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	csContext* csc = (csContext*)inst->context;
	int rc = CHANNEL_RC_OK;
	DISPLAY_CONTROL_MONITOR_LAYOUT layout = { 0 };

	if (!settings->DynamicResolutionUpdate || !csc->disp)
	{
		WLog_DBG(TAG, "send_monitor_update without disp channel");
		goto exit;
	}

	if ((GetTickCount64() - csc->lastSentDate) < RESIZE_MIN_DELAY)
	{
		WLog_DBG(TAG, "send_monitor_update too fast");
		goto exit;		
	}

	if (settings->SmartSizingWidth == targetWidth &&
	    settings->SmartSizingHeight == targetHeight)
	{
		WLog_DBG(TAG, "send_monitor_update nothing to do");
		goto exit;				
	}

	layout.Flags = DISPLAY_CONTROL_MONITOR_PRIMARY;
	layout.Top = layout.Left = 0;
	layout.Width = targetWidth;
	layout.Height = targetHeight;
	layout.Orientation = settings->DesktopOrientation;
	layout.DesktopScaleFactor = settings->DesktopScaleFactor;
	layout.DeviceScaleFactor = settings->DeviceScaleFactor;
	layout.PhysicalWidth = targetWidth;
	layout.PhysicalHeight = targetHeight;

	rc = IFCALLRESULT(CHANNEL_RC_OK, csc->disp->SendMonitorLayout, csc->disp, 1, &layout);
	status = rc == CHANNEL_RC_OK;

	if (!status)
	{
		WLog_ERR(TAG, "send_monitor_update failed (%d)", rc);
		goto exit;
	}

	settings->SmartSizingWidth = targetWidth;
	settings->SmartSizingHeight = targetHeight;
	csc->lastSentDate = GetTickCount64();

exit:
	return status;
}

void csharp_freerdp_send_cursor_event(void* instance, int x, int y, int flags)
{
	freerdp_input_send_mouse_event(((freerdp*)instance)->input, flags, x, y);
}

void csharp_freerdp_send_cursor_event_ex(void* instance, int x, int y, int flags)
{
	freerdp_input_send_extended_mouse_event(((freerdp*)instance)->input, flags, x, y);
}

void csharp_freerdp_send_clipboard_text(void* instance, const char* text)
{
	size_t len = 0;
	UINT32 formatId;
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;

	if(!ctxt->cliprdr || !ctxt->clipboard)
	{
		WLog_ERR(TAG, "Clipboard not initialized yet");
		return;
	}

	if (text)
		len = strlen(text);

	if (len)
	{
		formatId = ClipboardRegisterFormat(ctxt->clipboard, "UTF8_STRING");
		ClipboardSetData(ctxt->clipboard, formatId, (void*) text, (UINT32) len + 1);
	}
	else
	{
		ClipboardEmpty(ctxt->clipboard);
	}

	cs_cliprdr_send_client_format_list(ctxt->cliprdr);
}

void csharp_freerdp_send_clipboard_data(void* instance, BYTE* buffer, int length)
{
	int size;
	BYTE* data;
	UINT32 formatId;

	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;

	if(!ctxt->cliprdr || !ctxt->clipboard)
	{
		WLog_ERR(TAG, "Clipboard not initialized yet\n");
		return; /* Clipboard not ready yet.*/
	}

	formatId = ClipboardRegisterFormat(ctxt->clipboard, "UTF8_STRING");

	if (length)
	{
		size = length + 1;
		data = (BYTE*) malloc(size);

		if (!data)
			return;

		CopyMemory(data, buffer, size);
		data[size - 1] = '\0';
		ClipboardSetData(ctxt->clipboard, formatId, (void*) data, size);
		free(data);
	}
	else
	{
		ClipboardEmpty(ctxt->clipboard);
	}

	cs_cliprdr_send_client_format_list(ctxt->cliprdr);
}

void csharp_set_on_authenticate(void* instance, fnOnAuthenticate fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;
	
	ctxt->onAuthenticate = fn;
}

void csharp_set_on_clipboard_update(void* instance, fnOnClipboardUpdate fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;
	
	ctxt->onClipboardUpdate = fn;
}

void csharp_set_on_gateway_authenticate(void* instance, fnOnAuthenticate fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;
	
	ctxt->onGwAuthenticate = fn;
}

void csharp_set_on_verify_certificate(void* instance, pVerifyCertificateEx fn)
{
	freerdp* inst = (freerdp*)instance;
	
	inst->VerifyCertificateEx = fn;
}

void csharp_set_on_verify_x509_certificate(void* instance, pVerifyX509Certificate fn)
{
	freerdp* inst = (freerdp*)instance;
	
	inst->VerifyX509Certificate = fn;
}

void csharp_set_on_error(void* instance, fnOnError fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctxt = (csContext*)inst->context;
	
	ctxt->onError = fn;
}

void csharp_set_on_cursor_notifications(void* instance, fnOnNewCursor newCursor, fnOnFreeCursor freeCursor, fnOnSetCursor setCursor, fnOnDefaultCursor defaultCursor)
{
	freerdp* inst = (freerdp*)instance;
	csContext* csc = (csContext*)inst->context;
	
	csc->onNewCursor = newCursor;
	csc->onFreeCursor = freeCursor;
	csc->onSetCursor = setCursor;
	csc->onDefaultCursor = defaultCursor;
}

const char* csharp_get_error_info_string(int code)
{
	return freerdp_get_error_info_string(code);
}

int csharp_get_last_error(void* instance)
{
	freerdp* inst = (freerdp*)instance;
	rdpContext* ctx = (rdpContext*)inst->context;

	return freerdp_get_last_error(ctx);
}

void csharp_print_message(const char* tag, int level, uint32_t line, 
  const char* file, const char* function, const char* message)
{
	wLog* log = WLog_Get(tag);

	if (log && level >= (int) WLog_GetLogLevel(log))
		WLog_PrintMessage(log, WLOG_MESSAGE_TEXT, level, line, file, function, "%s", message);
}

void csharp_deallocate(void* ptr)
{
	if (ptr)
		free(ptr);
}

DWORD csharp_get_vk_from_keycode(DWORD keycode, DWORD flags)
{
	return GetVirtualKeyCodeFromKeycode(keycode, flags);
}

DWORD csharp_get_scancode_from_vk(DWORD keycode, DWORD flags)
{
	return GetVirtualScanCodeFromVirtualKeyCode(keycode, flags);
}

void csharp_freerdp_send_scancode(void* instance, int flags, DWORD scancode)
{
	freerdp* inst = (freerdp*)instance;
	
	freerdp_input_send_keyboard_event(inst->input, flags, scancode);
}

void csharp_freerdp_redirect_drive(void* instance, char* name, char* path)
{
	freerdp* inst = (freerdp*)instance;
	const char* d[] = { "drive", name, path};
	
	freerdp_client_add_device_channel(inst->settings, 3, d);
}

BOOL csharp_freerdp_set_smart_sizing(void* instance, BOOL smartSizing)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	if (settings->DynamicResolutionUpdate && smartSizing) /* Smart sizing and dynamic resolution are mutually exclusing */
		return FALSE;

	settings->SmartSizing = smartSizing;

	return TRUE;
}

void csharp_freerdp_set_load_balance_info(void* instance, const char* info)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->LoadBalanceInfo = (BYTE*)_strdup(info);
	settings->LoadBalanceInfoLength = (UINT32)strlen((char*) settings->LoadBalanceInfo);
}

void csharp_freerdp_set_performance_flags(void* instance, BOOL disableWallpaper, BOOL allowFontSmoothing, BOOL allowDesktopComposition,
					  BOOL bitmapCacheEnabled, BOOL disableFullWindowDrag, BOOL disableMenuAnims, BOOL disableThemes)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;
	
	settings->DisableWallpaper = disableWallpaper;
	settings->AllowFontSmoothing = allowFontSmoothing;
	settings->AllowDesktopComposition = allowDesktopComposition;
	settings->BitmapCacheEnabled = bitmapCacheEnabled;
	settings->DisableFullWindowDrag = disableFullWindowDrag;
	settings->DisableMenuAnims = disableMenuAnims;
	settings->DisableThemes = disableThemes;
}

void csharp_freerdp_set_tcpacktimeout(void* instance, UINT32 value)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	settings->TcpAckTimeout = value;
}

BOOL csharp_freerdp_set_value_for_name(void* instance, const char* name, const char* value)
{
	freerdp* inst = (freerdp*)instance;
	rdpSettings* settings = inst->settings;

	return freerdp_settings_set_value_for_name(settings, name, value);
}

void csharp_freerdp_sync_toggle_keys(void* instance)
{
#ifdef WIN32
	UINT16 syncFlags = 0;
	freerdp* inst = (freerdp*)instance;
	
	if (!inst)
		return;
	
	if (GetKeyState(VK_NUMLOCK))
		syncFlags |= KBD_SYNC_NUM_LOCK;
	
	if (GetKeyState(VK_CAPITAL))
		syncFlags |= KBD_SYNC_CAPS_LOCK;
	
	if (GetKeyState(VK_SCROLL))
		syncFlags |= KBD_SYNC_SCROLL_LOCK;
	
	if (GetKeyState(VK_KANA))
		syncFlags |= KBD_SYNC_KANA_LOCK;
	
	inst->input->FocusInEvent(inst->input, syncFlags);
#endif
}

FREERDP_API BOOL csharp_freerdp_input_send_focus_in_event(void* instance, uint16_t toggleStates)
{
	rdpInput* input = ((freerdp*)instance)->input;
	return freerdp_input_send_focus_in_event(input, toggleStates);
}

FREERDP_API BOOL csharp_freerdp_input_send_synchronize_event(void* instance, uint32_t flags)
{
	rdpInput* input = ((freerdp*)instance)->input;
	return freerdp_input_send_synchronize_event(input, flags);
}

FREERDP_API void csharp_freerdp_create_virtual_channels(void* instance, const char* channelNames)
{	
	char *r, *end;
	char* token = NULL;
	char** p;
	int status;
	size_t count;
	rdpSettings* settings = ((freerdp*)instance)->settings;

 	r = _strdup(channelNames);

	if(!r)
		return;

	token = end = r;

	while(token != NULL)
	{
		StrSep(&end, ",");
		p = freerdp_command_line_parse_comma_separated_values_offset(token, NULL, &count);
		status = freerdp_client_add_static_channel(settings, count, p);
		free(p);
		token = end;
	}

	free(r);
}

UINT csharp_freerdp_channel_write(void* instance, char* channelName, BSTR message, int size)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctx = (csContext*)inst->context;

	if(strcmp(channelName, "RDMJump") == 0)
	{
		return cs_channel_write(ctx->rdpjump, message, size);
	}
	else if(strcmp(channelName, "RDMCmd") == 0)
	{
		return cs_channel_write(ctx->rdpcmd, message, size);
	}
	else if(strcmp(channelName, "RDMLog") == 0)
	{
		return cs_channel_write(ctx->rdplog, message, size);
	}

	return -1;
}

void csharp_freerdp_channel_set_on_received_data(void* instance, fnOnChannelReceivedData fn)
{
	freerdp* inst = (freerdp*)instance;
	csContext* ctx = (csContext*)inst->context;

	ctx->onChannelReceivedData = fn;
}