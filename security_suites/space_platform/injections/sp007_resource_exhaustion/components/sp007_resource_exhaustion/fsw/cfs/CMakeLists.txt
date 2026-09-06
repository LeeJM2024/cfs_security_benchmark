cmake_minimum_required(VERSION 2.6.4)
project(SP007_RESOURCE_EXHAUSTION C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)
include_directories(${APPLICATION_PLATFORM_INC_LIST})

add_cfe_app(sp007
    src/sp007_resource_exhaustion_app.c
    src/sp007_resource_exhaustion_profiles.c
)
