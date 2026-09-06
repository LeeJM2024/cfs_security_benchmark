cmake_minimum_required(VERSION 2.6.4)
project(SP006_PAYLOAD_ABUSE C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)
include_directories(${APPLICATION_PLATFORM_INC_LIST})

include_directories(../../../arducam/fsw/cfs/platform_inc)
include_directories(../../../generic_reaction_wheel/fsw/cfs/platform_inc)
include_directories(../../../generic_thruster/fsw/cfs/platform_inc)

add_cfe_app(sp006
    src/sp006_payload_abuse_app.c
    src/sp006_payload_abuse_profiles.c
)
