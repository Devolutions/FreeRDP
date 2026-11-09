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

#define NOWPROTO_CLIENT_CALLBACKS_VERSION_2 2

	typedef struct s_nowproto_endpoint NowProtoEndpoint;

	/**
	 * One immutable offer identity. Retain before handing to asynchronous work,
	 * Release when finished. Each operation requires an owned reference; it is
	 * safe to Release a consumer reference from a reentrant callback.
	 * SubmitWrite copies nonempty data before returning. RequestClose is locally
	 * idempotent. Success with *queued=TRUE promises one OperationCompleted;
	 * success with *queued=FALSE is an already-closed Close, with no callback.
	 * Failure always sets *queued=FALSE and produces no callback.
	 * Completion may occur before submission returns on another thread.
	 * token is returned unchanged and is not dereferenced by native code.
	 * A closed endpoint survives plugin/session teardown until its last Release.
	 */
	struct s_nowproto_endpoint
	{
		void (*Retain)(NowProtoEndpoint* endpoint);
		void (*Release)(NowProtoEndpoint* endpoint);
		UINT (*SubmitWrite)
		(NowProtoEndpoint* endpoint, const BYTE* data, UINT32 size, void* token, BOOL* queued);
		UINT (*RequestClose)(NowProtoEndpoint* endpoint, void* token, BOOL* queued);
	};

	/**
	 * V2 requires asynchronous DVC mode. Callbacks run on the DVC worker. They must
	 * only copy/enqueue work, never wait for managed async work or destroy the
	 * session inline. Reentrant submissions only enqueue, never execute inline.
	 * No NOW plugin lock is held during callbacks. Core receive/close callbacks
	 * may hold the channel-table lock; callbacks must remain nonblocking.
	 * The endpoint and receive buffer are borrowed for the callback duration.
	 * Offer occurs on OnOpen, after the DVC create response; Closed occurs once
	 * for every offered endpoint, including disconnect/teardown.
	 * Keep custom and callback code alive until session teardown has completed.
	 */
	typedef struct
	{
		UINT32 size;
		UINT32 version;
		void* custom;
		void (*Offer)(void* custom, NowProtoEndpoint* endpoint);
		void (*Receive)(void* custom, NowProtoEndpoint* endpoint, const BYTE* data, size_t size);
		void (*Closed)(void* custom, NowProtoEndpoint* endpoint);
		/* Native operation result or ERROR_OPERATION_ABORTED at shutdown; not a
		 * transport delivery/remote acknowledgement. May follow Closed. */
		void (*OperationCompleted)(void* custom, NowProtoEndpoint* endpoint, void* token,
		                           UINT status);
	} NowProtoClientCallbacksV2;

	/**
	 * Explicit opt-in; the legacy four-pointer context layout is unchanged.
	 * Call before the first OnOpen (the first OnChannelConnected is early enough).
	 * The table is copied once and cannot be changed after opt-in or first open.
	 * V2 allows overlapping offers and replaces legacy Read/Write dispatch:
	 * legacy Write returns ERROR_INVALID_STATE; only endpoint submissions apply.
	 * Synchronous/replay mode returns ERROR_NOT_SUPPORTED.
	 * Without opt-in, the legacy single-channel behavior is preserved.
	 */
	FREERDP_API UINT freerdp_nowproto_client_set_callbacks(
	    NowProtoClientContext* context, const NowProtoClientCallbacksV2* callbacks);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNEL_NOWPROTO_CLIENT_NOWPROTO_H */
