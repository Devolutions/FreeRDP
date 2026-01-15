# FreeRDP: A Remote Desktop Protocol Implementation
# FreeRDP cmake build script
#
# Copyright 2024 Oleg Turovski <oleg2104@hotmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

define_channel_client("rdpecam")

if(NOT WITH_SWSCALE)
  message(FATAL_ERROR "WITH_SWSCALE required for CHANNEL_RDPECAM_CLIENT")
endif()

# WITH_FFMPEG only required when NOT using runtime loading
if(NOT WITH_SWSCALE_LOADING AND NOT WITH_FFMPEG)
  message(FATAL_ERROR "WITH_FFMPEG required for CHANNEL_RDPECAM_CLIENT when WITH_SWSCALE_LOADING=OFF")
endif()

# currently camera redirect client supported for platforms with Video4Linux only
find_package(V4L)
if(V4L_FOUND)
  set(WITH_V4L ON)
  add_compile_definitions("WITH_V4L")
else()
  message(FATAL_ERROR "libv4l-dev required for CHANNEL_RDPECAM_CLIENT")
endif()

option(RDPECAM_INPUT_FORMAT_H264 "[MS-RDPECAM] Enable H264 camera format (passthrough)" ON)
if(RDPECAM_INPUT_FORMAT_H264)
  add_compile_definitions("WITH_INPUT_FORMAT_H264")
endif()

# Handle swscale dependency based on loading mode
if(WITH_SWSCALE_LOADING)
  # Runtime loading - libavutil still needed for image utilities (LGPL, safe to link)
  # MJPG format requires libavcodec which is not available with runtime loading
  option(RDPECAM_INPUT_FORMAT_MJPG "[MS-RDPECAM] Enable MJPG camera format (NOT supported with runtime loading)" OFF)
  if(RDPECAM_INPUT_FORMAT_MJPG)
    message(WARNING "rdpecam: MJPG format cannot be enabled with runtime loading (requires libavcodec)")
    set(RDPECAM_INPUT_FORMAT_MJPG OFF CACHE BOOL "" FORCE)
  endif()

  # Find libavutil for image utility functions (av_image_fill_linesizes, av_image_fill_pointers)
  # Note: libavutil is LGPL licensed, safe to link dynamically (no GPL contamination)
  find_package(FFmpeg COMPONENTS AVUTIL)

  # Debug output
  message(STATUS "rdpecam: FFmpeg find results:")
  message(STATUS "  AVUTIL_FOUND = ${AVUTIL_FOUND}")
  message(STATUS "  FFmpeg_AVUTIL_FOUND = ${FFmpeg_AVUTIL_FOUND}")
  message(STATUS "  AVUTIL_LIBRARIES = ${AVUTIL_LIBRARIES}")
  message(STATUS "  AVUTIL_INCLUDE_DIRS = ${AVUTIL_INCLUDE_DIRS}")

  if(NOT AVUTIL_FOUND AND NOT FFmpeg_AVUTIL_FOUND)
    message(FATAL_ERROR
      "libavutil is required for rdpecam channel.\n"
      "Install: sudo apt-get install libavutil-dev (Debian/Ubuntu)\n"
      "         sudo dnf install ffmpeg-devel (Fedora)\n"
      "         sudo pacman -S ffmpeg (Arch)\n"
      "\n"
      "Note: libavutil is LGPL licensed (not GPL), safe to link with Apache 2.0 code.\n"
      "Only libswscale (GPL) is loaded at runtime, avoiding license contamination.")
  endif()

  include_directories(SYSTEM ${AVUTIL_INCLUDE_DIRS})
  message(STATUS "rdpecam: Using runtime swscale loading (swscale optional at runtime)")
  message(STATUS "rdpecam: libavutil linked (LGPL, safe - provides image utilities)")
  message(STATUS "rdpecam: MJPG format disabled (requires libavcodec, not supported with runtime loading)")
  set(${MODULE_PREFIX}_LIBS freerdp winpr ${AVUTIL_LIBRARIES})
else()
  # Direct linking - find and link FFmpeg/swscale
  option(RDPECAM_INPUT_FORMAT_MJPG "[MS-RDPECAM] Enable MJPG camera format" ON)
  if(RDPECAM_INPUT_FORMAT_MJPG)
    add_compile_definitions("WITH_INPUT_FORMAT_MJPG")
  endif()

  find_package(FFmpeg REQUIRED COMPONENTS SWSCALE AVUTIL AVCODEC)
  include_directories(SYSTEM ${SWSCALE_INCLUDE_DIRS} ${AVUTIL_INCLUDE_DIRS} ${AVCODEC_INCLUDE_DIRS})
  freerdp_client_pc_add_requires_private("libswscale")
  set(${MODULE_PREFIX}_LIBS freerdp winpr ${SWSCALE_LIBRARIES} ${AVUTIL_LIBRARIES} ${AVCODEC_LIBRARIES})
endif()

set(${MODULE_PREFIX}_SRCS camera_device_enum_main.c camera_device_main.c encoding.c)

add_channel_client_library(${MODULE_PREFIX} ${MODULE_NAME} ${CHANNEL_NAME} TRUE "DVCPluginEntry")

if(V4L_FOUND)
  add_channel_client_subsystem(${MODULE_PREFIX} ${CHANNEL_NAME} "v4l" "")
endif()
