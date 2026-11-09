/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Dynamic Virtual Channel Extension
 *
 * Copyright 2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CHANNEL_DRDYNVC_CLIENT_DRDYNVC_H
#define FREERDP_CHANNEL_DRDYNVC_CLIENT_DRDYNVC_H

#include <winpr/wtypes.h>
#include <freerdp/api.h>
#include <freerdp/dvc.h>

#include <freerdp/channels/drdynvc.h>

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Client Interface
	 */

	typedef struct s_drdynvc_client_context DrdynvcClientContext;

	/**
	 * Opt-in, connection-scoped asynchronous DVC worker dispatcher.
	 * Acquire only during plugin Initialize, with that callback's live manager.
	 * Synchronous/replay mode is unsupported (ERROR_NOT_SUPPORTED).
	 * Release the acquired reference when finished. Retained dispatchers survive
	 * teardown inertly, reject posts, and never attach to a subsequent connection.
	 * Post/Retain require an owned reference; do not race the final Release.
	 *
	 * Post always queues, even from the worker. Success transfers payload ownership:
	 * exactly one Complete runs on the worker, with Run's result or
	 * ERROR_OPERATION_ABORTED if shutdown prevents execution. Run/Complete must
	 * not block on managed work or destroy the session inline. No dispatcher or
	 * queue lock is held during either callback. Run must return normally.
	 * Completion may precede Post's return on another thread.
	 * Rejected posts transfer no ownership and invoke neither callback.
	 * Posting before worker startup returns ERROR_NOT_READY; after the shutdown
	 * fence it returns ERROR_NOT_CONNECTED. Complete releases the payload.
	 * All accepted callbacks finish before plugin Terminated.
	 */
	typedef struct s_drdynvc_dispatcher DrdynvcDispatcher;
	typedef UINT (*pcDrdynvcTaskRun)(void* payload);
	typedef void (*pcDrdynvcTaskComplete)(void* payload, UINT status);

	FREERDP_API UINT freerdp_drdynvc_dispatcher_acquire(IWTSVirtualChannelManager* manager,
	                                                    DrdynvcDispatcher** out);
	FREERDP_API void freerdp_drdynvc_dispatcher_retain(DrdynvcDispatcher* dispatcher);
	FREERDP_API void freerdp_drdynvc_dispatcher_release(DrdynvcDispatcher* dispatcher);
	FREERDP_API UINT freerdp_drdynvc_dispatcher_post(DrdynvcDispatcher* dispatcher,
	                                                 pcDrdynvcTaskRun run,
	                                                 pcDrdynvcTaskComplete complete, void* payload);

	/** @brief Dynamic channel stats struct. Contains statistic information for a single dynamic
	 * channel
	 *  @since version 3.28.0
	 */
	typedef struct
	{
		char channelName[256];
		uint32_t channelId;
		uint64_t bytesIn;
		uint64_t bytesOut;
		uint64_t fragmentsIn;
		uint64_t fragmentsOut;
		uint64_t packetsIn;
		uint64_t packetsOut;
	} DrdynvcClientChannelStat;

	typedef int (*pcDrdynvcGetVersion)(DrdynvcClientContext* context);
	typedef UINT (*pcDrdynvcOnChannelConnected)(DrdynvcClientContext* context, const char* name,
	                                            void* pInterface);
	typedef UINT (*pcDrdynvcOnChannelDisconnected)(DrdynvcClientContext* context, const char* name,
	                                               void* pInterface);
	typedef UINT (*pcDrdynvcOnChannelAttached)(DrdynvcClientContext* context, const char* name,
	                                           void* pInterface);
	typedef UINT (*pcDrdynvcOnChannelDetached)(DrdynvcClientContext* context, const char* name,
	                                           void* pInterface);

	/** @brief Function pointer type for dynamic channel statistics
	 *
	 *  @param context The dynamic channel context to query
	 *  @param pCount A pointer to a size_t that will be set to the amount of elements in the
	 * returned array. Must not be nullptr
	 *  @return An allocated array of \ref DrdynvcClientChannelStat of size \ref pCount. Use \ref
	 * free to free it.
	 *
	 *  @since version 3.28.0
	 */
	typedef DrdynvcClientChannelStat* (*pcDrdynvcGetChannelStats)(DrdynvcClientContext* context,
	                                                              size_t* pCount);

	struct s_drdynvc_client_context
	{
		ALIGN64 void* handle;
		ALIGN64 void* custom;
		ALIGN64 WINPR_ATTR_NODISCARD pcDrdynvcGetVersion GetVersion;
		ALIGN64 WINPR_ATTR_NODISCARD pcDrdynvcOnChannelConnected OnChannelConnected;
		ALIGN64 WINPR_ATTR_NODISCARD pcDrdynvcOnChannelDisconnected OnChannelDisconnected;
		ALIGN64 WINPR_ATTR_NODISCARD pcDrdynvcOnChannelAttached OnChannelAttached;
		ALIGN64 WINPR_ATTR_NODISCARD pcDrdynvcOnChannelDetached OnChannelDetached;
		ALIGN64 WINPR_ATTR_NODISCARD pcDrdynvcGetChannelStats
		    GetChannelStats; /**< Function returning the dynamic channel statistics.
		                      * @since version 3.28.0
		                      */
		ALIGN64 UINT64 reserved[56];
	};

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNEL_DRDYNVC_CLIENT_DRDYNVC_H */
