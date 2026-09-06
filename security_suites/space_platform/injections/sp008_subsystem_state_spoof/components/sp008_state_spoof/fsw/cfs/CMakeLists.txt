cmake_minimum_required(VERSION 2.6.4)
project(SP008_STATE_SPOOF C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)
include_directories(${APPLICATION_PLATFORM_INC_LIST})

add_cfe_app(sp008
    src/sp008_state_spoof_app.c
)
