#ifndef CS_DEVOLUTIONSRDP_H_
#define CS_DEVOLUTIONSRDP_H_

#include <freerdp/api.h>
#include <freerdp/freerdp.h>
#include <winpr/clipboard.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/client/disp.h>
#include "virtualchannel.h"

typedef BOOL (*fnChannelConnected)(void* context, const char* name, void* iface);
typedef BOOL (*fnChannelDisconnected)(void* context, const char* name, void* iface);
typedef void (*fnRegionUpdated)(void* rdp, int x, int y, int width, int height);
typedef void* (*fnDesktopSizeChanged)(void* rdp, int width, int height);
typedef void (*fnOnError)(void* context, int code);
typedef int (*fnLogonErrorInfo)(freerdp* instance, UINT32 data, UINT32 type);
typedef void (*fnOnClipboardUpdate)(void* context, byte* text, int length);
typedef void (*fnOnNewCursor)(void* context, void* pointer, BYTE* data, UINT32 x, UINT32 y, UINT32 w, UINT32 h, UINT32 hotX, UINT32 hotY);
typedef BYTE* (*fnOnFreeCursor)(void* context, void* pointer);
typedef void (*fnOnSetCursor)(void* context, void* pointer);
typedef void (*fnOnDefaultCursor)(void* context);
typedef BOOL (*fnOnAuthenticate)(void* context, 
	char* pszUsername, int cchUsername, 
	char* pszPassword, int cchPassword, 
	char* pszDoman, int cchDomain,
	rdp_auth_reason reason);

typedef struct csharp_context
{
	rdpContext _p;

	void* buffer;
	
	fnChannelConnected channelConnected;
	fnChannelDisconnected channelDisconnected;
	fnRegionUpdated regionUpdated;
	fnDesktopSizeChanged desktopSizeChanged;
	fnOnClipboardUpdate onClipboardUpdate;
	fnOnNewCursor onNewCursor;
	fnOnFreeCursor onFreeCursor;
	fnOnSetCursor onSetCursor;
	fnOnDefaultCursor onDefaultCursor;
	fnOnError onError;
	fnLogonErrorInfo onLogonErrorInfo;
	fnOnAuthenticate onAuthenticate;
	fnOnAuthenticate onGwAuthenticate;
	fnOnChannelReceivedData onChannelReceivedData;

	/* Legacy clipboard */
	wClipboard* clipboard;
	UINT32 numServerFormats;
	UINT32 requestedFormatId;
	HANDLE clipboardRequestEvent;
	CLIPRDR_FORMAT* serverFormats;
	CliprdrClientContext* cliprdr;
	/* Virtual channels */
	VirtChanContext* rdpcmd;
	VirtChanContext* rdpjump;
	VirtChanContext* rdplog;
	/* Dynamic resolution */
	DispClientContext* disp;
	UINT64 lastSentDate;
	/* Other */
	UINT16 audioQuality;
} csContext;

FREERDP_API BOOL csharp_configure_log_callback(int wlogLevel, wLogCallbackMessage_t fn);
FREERDP_API BOOL csharp_configure_log_file(int wlogLevel, const char* logPath, const char* logName);

FREERDP_API void* csharp_freerdp_new(void);
FREERDP_API void csharp_freerdp_free(void* instance);
FREERDP_API BOOL csharp_freerdp_connect(void* instance);
FREERDP_API BOOL csharp_freerdp_disconnect(void* instance);
FREERDP_API BOOL csharp_freerdp_abort_connect(void* instance);
FREERDP_API void csharp_freerdp_set_alternate_shell(void* instance, const char* shell);
FREERDP_API void csharp_freerdp_set_shell_working_directory(void* instance, const char* directory);
FREERDP_API void csharp_freerdp_set_initial_buffer(void* instance, void* buffer);
FREERDP_API void csharp_freerdp_set_on_channel_connected(void* instance, fnChannelConnected fn);
FREERDP_API void csharp_freerdp_set_on_channel_disconnected(void* instance, fnChannelDisconnected fn);
FREERDP_API void csharp_freerdp_set_on_region_updated(void* instance, fnRegionUpdated fn);
FREERDP_API void csharp_freerdp_set_on_desktop_size_changed(void* instance, fnDesktopSizeChanged fn);
FREERDP_API BOOL csharp_freerdp_set_client_hostname(void* instance, const char* clientHostname);
FREERDP_API void csharp_freerdp_set_console_mode(void* instance, BOOL useConsoleMode, BOOL useRestrictedAdminMode);
FREERDP_API void csharp_freerdp_set_redirect_clipboard(void* instance, BOOL redirectClipboard);
FREERDP_API BOOL csharp_freerdp_set_connection_info(void* instance, const char* hostname, const char* username, const char* password, const char* domain, UINT32 width, UINT32 height, UINT32 color_depth, UINT32 port, int codecLevel);
FREERDP_API void csharp_freerdp_set_security_info(void* instance, BOOL useTLS, BOOL useNLA, BOOL useRDP);
FREERDP_API BOOL csharp_freerdp_set_gateway_settings(void* instance, const char* hostname, UINT32 port, const char* username, const char* password, const char* domain, BOOL bypassLocal, BOOL httpTransport, BOOL rpcTransport);
FREERDP_API BOOL csharp_freerdp_set_data_directory(void* instance, const char* directory);
FREERDP_API void csharp_freerdp_set_support_display_control(void* instance, BOOL supportDisplayControl);
FREERDP_API BOOL csharp_freerdp_set_dynamic_resolution_update(void* instance, BOOL dynamicResolutionUpdate);
FREERDP_API void csharp_freerdp_set_load_balance_info(void* instance, const char* info);
FREERDP_API void csharp_freerdp_set_scale_factor(void* instance, UINT32 desktopScaleFactor, UINT32 deviceScaleFactor);
FREERDP_API void csharp_freerdp_set_performance_flags(void* instance,
							   BOOL disableWallpaper,
							   BOOL allowFontSmoothing,
							   BOOL allowDesktopComposition,
							   BOOL bitmapCacheEnabled,
							   BOOL disableFullWindowDrag,
							   BOOL disableMenuAnims,
							   BOOL disableThemes);
FREERDP_API void csharp_freerdp_performance_flags_split(void* instance);
FREERDP_API void csharp_freerdp_set_network_connection_type(void* instance, UINT32 connectionType);
FREERDP_API void csharp_freerdp_set_audio_quality_mode(void* instance, UINT16 qualityMode);
FREERDP_API void csharp_freerdp_set_tcpacktimeout(void* instance, UINT32 value);
FREERDP_API BOOL csharp_freerdp_set_value_for_name(void* settings, const char* name, const char* value);
FREERDP_API BOOL csharp_shall_disconnect(void* instance);
FREERDP_API BOOL csharp_waitforsingleobject(void* instance);
FREERDP_API BOOL csharp_check_event_handles(void* instance, void* buffer);

FREERDP_API void csharp_freerdp_send_clipboard_data(void* instance, BYTE* data, int length);
FREERDP_API void csharp_freerdp_send_clipboard_text(void* instance, const char* text);
FREERDP_API void csharp_freerdp_send_cursor_event(void* instance, int x, int y, int flags);
FREERDP_API void csharp_freerdp_send_cursor_event_ex(void* instance, int x, int y, int flags);
FREERDP_API void csharp_freerdp_send_input(void* instance, int keycode, BOOL down);
FREERDP_API BOOL csharp_freerdp_send_monitor_layout(void* instance, uint32_t targetWidth, uint32_t targetHeight);
FREERDP_API void csharp_freerdp_send_unicode(void* instance, int character);
FREERDP_API void csharp_freerdp_send_unicode_ex(void* instance, UINT16 character, BOOL down);
FREERDP_API DWORD csharp_get_vk_from_keycode(DWORD keycode, DWORD flags);
FREERDP_API DWORD csharp_get_scancode_from_vk(DWORD keycode, DWORD flags);
FREERDP_API void csharp_freerdp_send_vkcode(void* instance, int vkcode, BOOL down);
FREERDP_API void csharp_freerdp_send_scancode(void* instance, int flags, DWORD scancode);
FREERDP_API void csharp_freerdp_set_hyperv_info(void* instance, char* pcb);
FREERDP_API void csharp_freerdp_set_keyboard_layout(void* instance, int layoutID);
FREERDP_API BOOL csharp_freerdp_set_smart_sizing(void* instance, BOOL smartSizing);
FREERDP_API void csharp_freerdp_sync_toggle_keys(void* instance);
FREERDP_API BOOL csharp_freerdp_input_send_focus_in_event(void* instance, uint16_t toggleStates);
FREERDP_API BOOL csharp_freerdp_input_send_synchronize_event(void* instance, uint32_t flags);
FREERDP_API void csharp_set_on_authenticate(void* instance, fnOnAuthenticate fn);
FREERDP_API void csharp_set_on_clipboard_update(void* instance, fnOnClipboardUpdate fn);
FREERDP_API void csharp_set_on_gateway_authenticate(void* instance, fnOnAuthenticate fn);
FREERDP_API void csharp_set_on_verify_certificate(void* instance, pVerifyCertificateEx fn);
FREERDP_API void csharp_set_on_verify_x509_certificate(void* instance, pVerifyX509Certificate fn);
FREERDP_API void csharp_set_on_error(void* instance, fnOnError fn);
FREERDP_API void csharp_set_on_logon_error_info(void* instance, fnLogonErrorInfo fn);
FREERDP_API void csharp_set_on_cursor_notifications(void* instance, fnOnNewCursor newCursor, fnOnFreeCursor freeCursor, fnOnSetCursor setCursor, fnOnDefaultCursor defaultCursor);
FREERDP_API void csharp_set_on_gateway_message(void* instance, pPresentGatewayMessage fn);
FREERDP_API uint32_t csharp_get_last_error(void* instance);
FREERDP_API uint32_t csharp_get_nla_sspi_error(void* instance);
FREERDP_API void csharp_print_message(const char* tag, int level, uint32_t line, const char* file, const char* function, const char* message);
FREERDP_API void csharp_deallocate(void* ptr);

FREERDP_API void csharp_freerdp_redirect_drive(void* instance, char* name, char* path);
FREERDP_API void csharp_freerdp_set_redirect_all_drives(void* instance, BOOL redirect);
FREERDP_API void csharp_freerdp_set_redirect_home_drive(void* instance, BOOL redirect);
FREERDP_API void csharp_freerdp_set_redirect_audio(void* instance, int redirectSound, BOOL redirectCapture);
FREERDP_API void csharp_freerdp_set_redirect_printers(void* instance, BOOL redirect);
FREERDP_API void csharp_freerdp_set_redirect_smartcards(void* instance, BOOL redirect);

FREERDP_API void csharp_freerdp_create_virtual_channels(void* instance, const char* channelNames);
FREERDP_API UINT csharp_freerdp_channel_write(void* instance, char* channelName, BSTR message, int size);
FREERDP_API void csharp_freerdp_channel_set_on_received_data(void* instance, fnOnChannelReceivedData fn);

#endif /* CS_DEVOLUTIONSRDP_H_ */
