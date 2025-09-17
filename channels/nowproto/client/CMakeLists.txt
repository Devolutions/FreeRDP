define_channel_client("nowproto")

set(${MODULE_PREFIX}_SRCS nowproto_main.c nowproto_main.h)

set(${MODULE_PREFIX}_LIBS winpr)

include_directories(..)

add_channel_client_library(${MODULE_PREFIX} ${MODULE_NAME} ${CHANNEL_NAME} TRUE "DVCPluginEntry")
