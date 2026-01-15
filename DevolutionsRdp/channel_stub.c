/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * DevolutionsRdp - Static Channel Symbol References
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

#include <winpr/wtypes.h>

/**
 * This file contains stub references to static channel entry points
 * to force the linker to include them from libfreerdp-client.
 *
 * Without these references, the linker may discard the channel symbols
 * from the static library since nothing directly calls them.
 * The actual channel loading happens through function pointer tables
 * that are populated at build time.
 */

/* Declare external channel entry points */
#ifdef __cplusplus
extern "C"
{
#endif

	/* rdpecam dynamic virtual channel entry point */
	extern UINT rdpecam_DVCPluginEntry(void* pEntryPoints);

	/* v4l subsystem entry point for rdpecam */
	extern UINT v4l_freerdp_rdpecam_client_subsystem_entry(void* pEntryPoints);

#ifdef __cplusplus
}
#endif

/**
 * Force linker to include static channel symbols.
 * This function is never called at runtime - it exists solely to create
 * references to the channel entry points so the linker includes them.
 */
void** devolutions_rdp_force_static_channel_symbols(void)
{
	static void* symbols[] = { (void*)rdpecam_DVCPluginEntry,
		                       (void*)v4l_freerdp_rdpecam_client_subsystem_entry, NULL };

	return symbols;
}
