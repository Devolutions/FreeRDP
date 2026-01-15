/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * swscale Runtime Loading
 *
 * Copyright 2025 Devolutions Inc.
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

#ifndef FREERDP_LIB_CODEC_SWSCALE_LOADER_H
#define FREERDP_LIB_CODEC_SWSCALE_LOADER_H

#include <freerdp/config.h>

#if defined(WITH_SWSCALE)

#if defined(WITH_SWSCALE_LOADING)

#include <winpr/wtypes.h>

// Forward declarations to avoid requiring swscale headers at compile time
struct SwsContext;
enum AVPixelFormat;

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * @brief Initialize and load the swscale library at runtime
	 * @return TRUE if swscale is available and loaded successfully, FALSE otherwise
	 */
	BOOL freerdp_swscale_init(void);

	/**
	 * @brief Check if swscale is available
	 * @return TRUE if swscale library is loaded and ready to use
	 */
	BOOL freerdp_swscale_available(void);

	/**
	 * @brief Get a swscale context (wrapper for sws_getContext)
	 */
	struct SwsContext* freerdp_sws_getContext(int srcW, int srcH, int srcFormat, int dstW,
	                                          int dstH, int dstFormat, int flags, void* srcFilter,
	                                          void* dstFilter, const double* param);

	/**
	 * @brief Scale image data (wrapper for sws_scale)
	 */
	int freerdp_sws_scale(struct SwsContext* ctx, const uint8_t* const srcSlice[],
	                      const int srcStride[], int srcSliceY, int srcSliceH,
	                      uint8_t* const dst[], const int dstStride[]);

	/**
	 * @brief Free swscale context (wrapper for sws_freeContext)
	 */
	void freerdp_sws_freeContext(struct SwsContext* ctx);

#ifdef __cplusplus
}
#endif

#endif /* WITH_SWSCALE_LOADING */

#endif /* WITH_SWSCALE */

#endif /* FREERDP_LIB_CODEC_SWSCALE_LOADER_H */
