
set(MODULE_NAME "DevolutionsRdp")
set(MODULE_PREFIX "DEVOLUTIONS_RDP")

set(OUTPUT_NAME "DevolutionsRdp")

set(RDP_TIE_VERSION "1.0.0")
set(RDP_TIE_NAME "DevolutionsRdp")
set(RDP_TIE_VENDOR "Devolutions Inc.")
set(RDP_TIE_COPYRIGHT "Copyright 2020 ${RDP_TIE_VENDOR} All Rights Reserved.")

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(${MODULE_PREFIX}_HEADERS
	clipboard.h
	cursor.h
	virtualchannel.h
	DevolutionsRdp.h)

set(${MODULE_PREFIX}_SOURCES
	${${MODULE_PREFIX}_HDRS}
	clipboard.c
	headless.c
	cursor.c
	virtualchannel.c
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

if(ANDROID)
	target_link_libraries(${MODULE_NAME} log dl m)
endif()

if(WIN32)
	target_link_libraries(${MODULE_NAME} winmm ntdsapi rpcrt4 dbghelp ncrypt)
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

install(TARGETS DevolutionsRdp
	EXPORT DevolutionsRdp-target
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib)
#endif()
