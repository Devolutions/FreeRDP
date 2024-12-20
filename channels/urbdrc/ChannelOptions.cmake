if(IOS OR ANDROID)
  set(OPTION_DEFAULT OFF)
  set(OPTION_CLIENT_DEFAULT OFF)
  set(OPTION_SERVER_DEFAULT OFF)
else()
  set(OPTION_DEFAULT ON)
  set(OPTION_CLIENT_DEFAULT ON)
  set(OPTION_SERVER_DEFAULT OFF)
endif()

define_channel_options(
  NAME
  "urbdrc"
  TYPE
  "dynamic"
  DESCRIPTION
  "USB Devices Virtual Channel Extension"
  SPECIFICATIONS
  "[MS-RDPEUSB]"
  DEFAULT
  ${OPTION_DEFAULT}
)

define_channel_client_options(${OPTION_CLIENT_DEFAULT})
define_channel_server_options(${OPTION_SERVER_DEFAULT})
