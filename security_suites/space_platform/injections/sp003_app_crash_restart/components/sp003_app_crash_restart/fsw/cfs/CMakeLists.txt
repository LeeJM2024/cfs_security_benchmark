cmake_minimum_required(VERSION 2.6.4)
project(SP003_APP_CRASH_RESTART C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)
include_directories(${APPLICATION_PLATFORM_INC_LIST})

add_cfe_app(sp003_crash
    src/sp003_app_crash_restart_app.c
)
