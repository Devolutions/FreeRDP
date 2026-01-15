
set(MODULE_NAME "DevolutionsRdp")
set(MODULE_PREFIX "DEVOLUTIONS_RDP")

set(OUTPUT_NAME "DevolutionsRdp")

set(RDP_TIE_VERSION "1.0.0")
set(RDP_TIE_NAME "DevolutionsRdp")
set(RDP_TIE_VENDOR "Devolutions Inc.")
set(RDP_TIE_COPYRIGHT "Copyright 2025 ${RDP_TIE_VENDOR} All Rights Reserved.")

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(${MODULE_PREFIX}_HEADERS
	clipboard.h
	cursor.h
	headless.h
	virtualchannel.h
	DevolutionsRdp.h)

set(${MODULE_PREFIX}_SOURCES
	${${MODULE_PREFIX}_HDRS}
	clipboard.c
	headless.c
	cursor.c
	virtualchannel.c
	channel_stub.c
	DevolutionsRdp.c)

set(${MODULE_PREFIX}_RESOURCES "")

if(WIN32)
	include(WindowsRC)

	set(${MODULE_PREFIX}_RESOURCES
		DevolutionsRdp.rc)

	windows_rc_generate_version_info(
		NAME "${RDP_TIE_NAME}" TYPE "DLL"
		VERSION "${RDP_TIE_VERSION}"
		FILENAME "${OUTPUT_NAME}.dll"
		VENDOR "${RDP_TIE_VENDOR}"
		COPYRIGHT "${RDP_TIE_COPYRIGHT}"
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

	source_group("Resources" FILES ${${MODULE_PREFIX}_RESOURCES})
endif()

if(MSVC)
	include(MSVCRuntime)
	if(NOT DEFINED MSVC_RUNTIME)
		set(MSVC_RUNTIME "dynamic")
	endif()
	configure_msvc_runtime()
endif()

set(TARGET_TYPE "SHARED")

add_library(${MODULE_NAME} ${TARGET_TYPE} ${${MODULE_PREFIX}_HEADERS} ${${MODULE_PREFIX}_SOURCES} ${${MODULE_PREFIX}_RESOURCES})

target_link_libraries(${MODULE_NAME} freerdp freerdp-client winpr)

# if (NOT DEFINED PNG_LIBRARY AND APPLE AND NOT IOS)
# 	find_library(PNG_LIBRARY png)
# 	message(STATUS "PNG_LIBRARY = ${PNG_LIBRARY}")
# endif()

if (DEFINED PNG_LIBRARY)
    target_link_libraries(${MODULE_NAME} ${PNG_LIBRARY})
endif()

# if (NOT DEFINED JPEG_LIBRARY AND APPLE AND NOT IOS)
# 	find_library(JPEG_LIBRARY jpeg)
# 	message(STATUS "JPEG_LIBRARY = ${JPEG_LIBRARY}")
# endif()

if (DEFINED JPEG_LIBRARY)
    target_link_libraries(${MODULE_NAME} ${JPEG_LIBRARY})
endif()

# swscale support for image scaling and rdpecam (camera redirection)
# IMPORTANT: DevolutionsRdp MUST use runtime loading to avoid GPL license contamination
# We never link swscale directly - it's always loaded at runtime
if (WITH_SWSCALE)
	# Safety check: DevolutionsRdp requires runtime loading
	if (NOT WITH_SWSCALE_LOADING)
		message(FATAL_ERROR
			"DevolutionsRdp requires WITH_SWSCALE_LOADING=ON to avoid GPL contamination. "
			"Direct linking of swscale is NOT permitted for DevolutionsRdp. "
			"Please rebuild with -DWITH_SWSCALE_LOADING=ON")
	endif()

	# Runtime loading confirmed - no FFmpeg dependency at build or link time
	message(STATUS "DevolutionsRdp: FFmpeg will be loaded at runtime (NO build/link dependencies)")
	message(STATUS "  - libswscale (GPL): Loaded at runtime via dlopen")
	message(STATUS "  - libavutil (LGPL): Loaded at runtime via dlopen")
	message(STATUS "  - Image scaling: Available if user has FFmpeg installed")
	message(STATUS "  - rdpecam channel: Available if user has FFmpeg installed")
	message(STATUS "  - No GPL contamination: nothing is statically or dynamically linked")

	# Verify we're not accidentally linking swscale
	get_target_property(_DEVRDP_LINK_LIBS ${MODULE_NAME} LINK_LIBRARIES)
	if (_DEVRDP_LINK_LIBS)
		string(TOLOWER "${_DEVRDP_LINK_LIBS}" _DEVRDP_LINK_LIBS_LOWER)
		if ("${_DEVRDP_LINK_LIBS_LOWER}" MATCHES "swscale")
			message(FATAL_ERROR
				"SAFETY CHECK FAILED: DevolutionsRdp is accidentally linking swscale! "
				"This violates GPL licensing requirements. "
				"Link libraries: ${_DEVRDP_LINK_LIBS}")
		endif()
	endif()
endif()

if(ANDROID)
	target_link_libraries(${MODULE_NAME} log dl m)
endif()

if(WIN32)
	target_link_libraries(${MODULE_NAME} winmm ntdsapi rpcrt4 dbghelp ncrypt shlwapi)
endif()

if(APPLE)
	find_library(CORE_AUDIO CoreAudio)
	find_library(AUDIO_TOOLBOX AudioToolbox)
	find_library(CORE_FOUNDATION CoreFoundation)
	find_library(CORE_SERVICES CoreServices)
	target_link_libraries(${MODULE_NAME} "${CORE_AUDIO}")
	target_link_libraries(${MODULE_NAME} "${AUDIO_TOOLBOX}")
	target_link_libraries(${MODULE_NAME} "${CORE_FOUNDATION}")
	target_link_libraries(${MODULE_NAME} "${CORE_SERVICES}")

	if(IOS)
		find_library(FOUNDATION Foundation)
		target_link_libraries(${MODULE_NAME} "${FOUNDATION}")
	endif()

	if(NOT IOS)
		find_library(AUDIO_UNIT AudioUnit)
		target_link_libraries(${MODULE_NAME} "${AUDIO_UNIT}")
	endif()
endif()

set_target_properties(${MODULE_NAME} PROPERTIES PREFIX "")
set_target_properties(${MODULE_NAME} PROPERTIES OUTPUT_NAME "${OUTPUT_NAME}")

# FINAL SAFETY CHECK: Verify swscale was never linked (GPL license protection)
if (WITH_SWSCALE)
	get_target_property(_FINAL_LINK_LIBS ${MODULE_NAME} LINK_LIBRARIES)
	if (_FINAL_LINK_LIBS)
		string(TOLOWER "${_FINAL_LINK_LIBS}" _FINAL_LINK_LIBS_LOWER)
		if ("${_FINAL_LINK_LIBS_LOWER}" MATCHES "swscale")
			message(FATAL_ERROR
				"\n"
				"========================================================================\n"
				"CRITICAL GPL LICENSE VIOLATION DETECTED!\n"
				"========================================================================\n"
				"DevolutionsRdp is linking against swscale library directly!\n"
				"This creates a GPL license obligation that violates our Apache 2.0 license.\n"
				"\n"
				"Linked libraries: ${_FINAL_LINK_LIBS}\n"
				"\n"
				"DevolutionsRdp MUST use runtime loading (WITH_SWSCALE_LOADING=ON).\n"
				"Build aborted to prevent GPL contamination.\n"
				"========================================================================\n")
		endif()
	endif()
	message(STATUS "✓ DevolutionsRdp: GPL safety check passed - no swscale linkage detected")
endif()

install(TARGETS DevolutionsRdp
	EXPORT DevolutionsRdp-target
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib)
#endif()
