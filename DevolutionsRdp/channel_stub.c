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
 * This file contains stub references to force the linker to include
 * static channel entry points from libfreerdp-client.
 *
 * Without these references, the linker may discard the channel symbols
 * from the static library since nothing directly calls them.
 * The actual channel loading happens through function pointer tables
 * that are populated at build time and looked up by
 * freerdp_channels_load_static_addin_entry().
 */

#ifdef __cplusplus
extern "C"
{
#endif

	/* Forward declaration of the static addin loader function */
	extern void* freerdp_channels_load_static_addin_entry(const char*, const char*, const char*,
	                                                       unsigned long);

	/* rdpecam channel entry points - these need explicit references */
	extern unsigned int rdpecam_DVCPluginEntry(void* pEntryPoints);
	extern unsigned int v4l_freerdp_rdpecam_client_subsystem_entry(void* pEntryPoints);

	/* Forward declare subsystem table to prevent linker from stripping it */
	typedef struct
	{
		const char* name;
		const char* type;
		unsigned int (*entry)(void*);
	} STATIC_SUBSYSTEM_ENTRY;
	extern const STATIC_SUBSYSTEM_ENTRY CLIENT_RDPECAM_SUBSYSTEM_TABLE[];

#ifdef __cplusplus
}
#endif

/**
 * Array of static channel symbols that must be included.
 * This is intentionally non-static to prevent the linker from discarding it.
 * The volatile qualifier prevents the compiler from optimizing away references.
 */
volatile const void* devolutions_rdp_static_channel_symbols[] = {
	/* Reference the loader function - this will pull in tables.c.o with all tables */
	(const void*)freerdp_channels_load_static_addin_entry,
	/* Reference the actual entry points */
	(const void*)rdpecam_DVCPluginEntry,
	(const void*)v4l_freerdp_rdpecam_client_subsystem_entry,
	NULL
};

/**
 * Force linker to include static channel entry points.
 * This function uses volatile to prevent the compiler from optimizing away
 * the symbol references.
 */
void devolutions_rdp_force_static_channel_symbols(void)
{
	/* Access the volatile array to ensure it's not optimized away */
	volatile const void* ptr = devolutions_rdp_static_channel_symbols[0];
	(void)ptr;

	/* Access subsystem table at runtime to prevent section garbage collection */
	volatile const void* table_ref = (const void*)CLIENT_RDPECAM_SUBSYSTEM_TABLE;
	(void)table_ref;
}
