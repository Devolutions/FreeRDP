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

#include <freerdp/config.h>

#if defined(WITH_SWSCALE) && defined(WITH_SWSCALE_LOADING)

#include <winpr/library.h>
#include <winpr/assert.h>
#include <winpr/environment.h>
#include <freerdp/log.h>

#include "swscale_loader.h"

#define TAG FREERDP_TAG("codec.swscale")

// Forward declare AVPixelFormat enum values we need
enum AVPixelFormat
{
	AV_PIX_FMT_NONE = -1
};

// Function pointer types
typedef struct SwsContext* (*pSws_getContext)(int srcW, int srcH, int srcFormat, int dstW,
                                               int dstH, int dstFormat, int flags,
                                               void* srcFilter, void* dstFilter,
                                               const double* param);
typedef int (*pSws_scale)(struct SwsContext* c, const uint8_t* const srcSlice[],
                          const int srcStride[], int srcSliceY, int srcSliceH,
                          uint8_t* const dst[], const int dstStride[]);
typedef void (*pSws_freeContext)(struct SwsContext* c);

typedef struct
{
	HMODULE lib;
	pSws_getContext getContext;
	pSws_scale scale;
	pSws_freeContext freeContext;
	BOOL initialized;
	BOOL available;
} SWSCALE_LIBRARY;

static SWSCALE_LIBRARY g_swscale = { 0 };

static const char* swscale_library_names[] = {
#if defined(_WIN32)
	"swscale-9.dll", "swscale-8.dll", "swscale-7.dll", "swscale-6.dll", "swscale.dll"
#elif defined(__APPLE__)
	"libswscale.dylib",
	"libswscale.9.dylib",
	"libswscale.8.dylib",
	"libswscale.7.dylib",
	"libswscale.6.dylib"
#else
	"libswscale.so.9", "libswscale.so.8", "libswscale.so.7", "libswscale.so.6", "libswscale.so"
#endif
};

static BOOL swscale_load_library(const char* name)
{
	WINPR_ASSERT(name);

	WLog_DBG(TAG, "Attempting to load swscale library: %s", name);

	g_swscale.lib = LoadLibraryA(name);
	if (!g_swscale.lib)
	{
		WLog_DBG(TAG, "Failed to load %s", name);
		return FALSE;
	}

	g_swscale.getContext =
	    (pSws_getContext)(void*)GetProcAddress(g_swscale.lib, "sws_getContext");
	g_swscale.scale = (pSws_scale)(void*)GetProcAddress(g_swscale.lib, "sws_scale");
	g_swscale.freeContext =
	    (pSws_freeContext)(void*)GetProcAddress(g_swscale.lib, "sws_freeContext");

	if (!g_swscale.getContext || !g_swscale.scale || !g_swscale.freeContext)
	{
		WLog_WARN(TAG, "Failed to load required functions from %s", name);
		FreeLibrary(g_swscale.lib);
		g_swscale.lib = NULL;
		return FALSE;
	}

	WLog_INFO(TAG, "Successfully loaded swscale library: %s", name);
	return TRUE;
}

static char* swscale_library_path_from_environment(const char* name)
{
	char* env = NULL;

	WINPR_ASSERT(name);

	if (!name)
		return NULL;

	const DWORD size = GetEnvironmentVariableX(name, env, 0);

	if (size <= 1)
	{
		WLog_DBG(TAG, "No environment variable '%s'", name);
		return NULL;
	}

	env = calloc(size, sizeof(char));

	if (!env)
		return NULL;

	const DWORD rc = GetEnvironmentVariableX(name, env, size);

	if (rc != size - 1)
	{
		WLog_WARN(TAG, "Environment variable '%s' has invalid size", name);
		free(env);
		return NULL;
	}

	return env;
}

BOOL freerdp_swscale_init(void)
{
	if (g_swscale.initialized)
		return g_swscale.available;

	g_swscale.initialized = TRUE;
	g_swscale.available = FALSE;

	// Try environment variable first
	char* env_path = swscale_library_path_from_environment("FREERDP_SWSCALE_LIBRARY_PATH");
	if (env_path)
	{
		WLog_INFO(TAG, "Using swscale library path from environment: %s", env_path);
		if (swscale_load_library(env_path))
		{
			g_swscale.available = TRUE;
			free(env_path);
			return TRUE;
		}
		free(env_path);
	}

	// Try default library names
	WLog_DBG(TAG, "Searching for swscale library in default locations");
	for (size_t i = 0; i < ARRAYSIZE(swscale_library_names); i++)
	{
		if (swscale_load_library(swscale_library_names[i]))
		{
			g_swscale.available = TRUE;
			return TRUE;
		}
	}

	WLog_INFO(TAG,
	          "swscale library not found - image scaling features will not be available. "
	          "Install FFmpeg to enable these features.");
	return FALSE;
}

BOOL freerdp_swscale_available(void)
{
	return freerdp_swscale_init() && g_swscale.available;
}

struct SwsContext* freerdp_sws_getContext(int srcW, int srcH, int srcFormat, int dstW, int dstH,
                                          int dstFormat, int flags, void* srcFilter,
                                          void* dstFilter, const double* param)
{
	if (!freerdp_swscale_available())
	{
		WLog_WARN(TAG, "sws_getContext called but swscale not available");
		return NULL;
	}

	WINPR_ASSERT(g_swscale.getContext);
	return g_swscale.getContext(srcW, srcH, srcFormat, dstW, dstH, dstFormat, flags, srcFilter,
	                            dstFilter, param);
}

int freerdp_sws_scale(struct SwsContext* ctx, const uint8_t* const srcSlice[],
                      const int srcStride[], int srcSliceY, int srcSliceH, uint8_t* const dst[],
                      const int dstStride[])
{
	if (!freerdp_swscale_available())
	{
		WLog_WARN(TAG, "sws_scale called but swscale not available");
		return -1;
	}

	if (!ctx)
	{
		WLog_WARN(TAG, "sws_scale called with NULL context");
		return -1;
	}

	WINPR_ASSERT(g_swscale.scale);
	return g_swscale.scale(ctx, srcSlice, srcStride, srcSliceY, srcSliceH, dst, dstStride);
}

void freerdp_sws_freeContext(struct SwsContext* ctx)
{
	if (!freerdp_swscale_available())
		return;

	if (!ctx)
		return;

	WINPR_ASSERT(g_swscale.freeContext);
	g_swscale.freeContext(ctx);
}

#endif /* WITH_SWSCALE && WITH_SWSCALE_LOADING */
