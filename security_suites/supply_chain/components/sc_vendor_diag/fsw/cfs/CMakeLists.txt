cmake_minimum_required(VERSION 2.6.4)
project(SC_VENDOR_DIAG C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)
include_directories(${APPLICATION_PLATFORM_INC_LIST})

add_cfe_app(sc_vendor_diag
    src/sc_vendor_diag_app.c
)
