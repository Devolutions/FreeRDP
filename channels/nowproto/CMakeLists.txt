define_channel("nowproto")

if(WITH_CLIENT_CHANNELS)
  add_channel_client(${MODULE_PREFIX} ${CHANNEL_NAME})
endif()
