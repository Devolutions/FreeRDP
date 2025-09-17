#ifndef FREERDP_CHANNEL_NOWPROTO_CLIENT_NOWPROTO_H
#define FREERDP_CHANNEL_NOWPROTO_CLIENT_NOWPROTO_H

#include <freerdp/channels/nowproto.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct s_nowproto_client_context NowProtoClientContext;

	typedef UINT (*pcWrite)(NowProtoClientContext* context, void* data, int size);
	typedef UINT (*pcRead)(NowProtoClientContext* context, void* data, size_t size);

	struct s_nowproto_client_context
	{
		void* handle;
		void* custom;

		pcWrite Write;
		pcRead Read;
	};

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNEL_NOWPROTO_CLIENT_NOWPROTO_H */
