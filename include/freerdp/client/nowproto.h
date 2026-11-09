#ifndef FREERDP_CHANNEL_NOWPROTO_CLIENT_NOWPROTO_H
#define FREERDP_CHANNEL_NOWPROTO_CLIENT_NOWPROTO_H

#include <freerdp/channels/nowproto.h>
#include <freerdp/api.h>

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

#define NOWPROTO_CLIENT_CALLBACKS_VERSION_3 3

	typedef struct s_nowproto_endpoint NowProtoEndpoint;

	/**
	 * One retained offer identity, never a reusable wire ID. Retain before handing
	 * to asynchronous work; Release every owned reference, even after teardown.
	 * Operations require an owned reference; do not race the final Release.
	 *
	 * Write requires nonempty bytes and synchronously copies/submits them using
	 * the existing transport. The caller retains the buffer until Write returns.
	 * Result is native submission status, not delivery/remote acknowledgement.
	 * After retirement or native closure, Write returns ERROR_NOT_CONNECTED.
	 * Writes are serialized with each other and native callback destruction.
	 * Do not call Write inline from a native callback.
	 *
	 * Retire is idempotent LOCAL retirement: rejects subsequent writes and
	 * suppresses future Receive admission. It never calls native Close or emits
	 * Closed. An already-admitted Receive can run/finish after Retire returns.
	 * Native closure remains remote/session-owned; Closed still occurs then.
	 * Retire may wait for an in-flight Write. It is safe inline from a callback,
	 * but nonblocking actor-side retirement is preferred.
	 */
	struct s_nowproto_endpoint
	{
		void (*Retain)(NowProtoEndpoint* endpoint);
		void (*Release)(NowProtoEndpoint* endpoint);
		UINT (*Write)(NowProtoEndpoint* endpoint, const BYTE* data, UINT32 size);
		UINT (*Retire)(NowProtoEndpoint* endpoint);
	};

	/**
	 * Callbacks run on the native DVC callback thread (the drdynvc worker in
	 * default asynchronous mode). Only copy/enqueue work; never wait for managed
	 * work, perform inline Write, or destroy the session. No NOW lock is held
	 * while calling user code; core receive/close may hold channel-table locks.
	 * Endpoint and receive buffer are borrowed for the callback duration.
	 * Offer occurs on OnOpen after CREATE response. Closed is native closure,
	 * once per offered endpoint, including remote/session teardown.
	 * Keep delegates/custom state alive until native teardown returns, even
	 * after logical retirement. Use actor generation fencing for queued events.
	 */
	typedef struct
	{
		UINT32 size;
		UINT32 version;
		void* custom;
		void (*Offer)(void* custom, NowProtoEndpoint* endpoint);
		void (*Receive)(void* custom, NowProtoEndpoint* endpoint, const BYTE* data, size_t size);
		void (*Closed)(void* custom, NowProtoEndpoint* endpoint);
	} NowProtoClientCallbacksV3;

	/**
	 * Explicit opt-in; legacy four-pointer context layout is unchanged.
	 * Install once before first OnOpen (first NOW OnChannelConnected is early
	 * enough); the table is copied/frozen. V3 accepts overlapping offers and
	 * disables legacy Read/Write (Write returns ERROR_INVALID_STATE).
	 * No worker dispatcher, global synchronous mode or active native close.
	 * Legacy mode retains single-channel behavior; Write requires nonempty data.
	 */
	FREERDP_API UINT freerdp_nowproto_client_set_callbacks(
	    NowProtoClientContext* context, const NowProtoClientCallbacksV3* callbacks);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNEL_NOWPROTO_CLIENT_NOWPROTO_H */
