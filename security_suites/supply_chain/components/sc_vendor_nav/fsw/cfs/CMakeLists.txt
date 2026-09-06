cmake_minimum_required(VERSION 2.6.4)
project(SC_VENDOR_NAV C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)
include_directories(${APPLICATION_PLATFORM_INC_LIST})

# Payload adapters are compiled into the vendor carrier.  The installer
# materializes these files from the corresponding SP implementation; no SP
# application is added to the mission startup list.
include_directories(src/payload_adapters)
include_directories(../../../generic_adcs/fsw/cfs/src)
include_directories(../../../generic_adcs/fsw/cfs/platform_inc)
include_directories(../../../generic_eps/fsw/cfs/src)
include_directories(../../../generic_eps/fsw/cfs/platform_inc)
include_directories(../../../generic_reaction_wheel/fsw/cfs/src)
include_directories(../../../generic_reaction_wheel/fsw/cfs/platform_inc)
include_directories(../../../generic_torquer/fsw/cfs/src)
include_directories(../../../generic_torquer/fsw/cfs/platform_inc)
include_directories(../../../generic_thruster/fsw/cfs/src)
include_directories(../../../generic_thruster/fsw/cfs/platform_inc)
include_directories(../../../generic_radio/fsw/cfs/src)
include_directories(../../../generic_radio/fsw/cfs/platform_inc)
include_directories(../../../novatel_oem615/fsw/cfs/src)
include_directories(../../../novatel_oem615/fsw/cfs/platform_inc)
include_directories(../../../generic_imu/fsw/cfs/src)
include_directories(../../../generic_imu/fsw/cfs/platform_inc)
include_directories(../../../generic_mag/fsw/cfs/src)
include_directories(../../../generic_mag/fsw/cfs/platform_inc)
include_directories(../../../generic_css/fsw/cfs/src)
include_directories(../../../generic_css/fsw/cfs/platform_inc)
include_directories(../../../generic_fss/fsw/cfs/src)
include_directories(../../../generic_fss/fsw/cfs/platform_inc)
include_directories(../../../generic_star_tracker/fsw/cfs/src)
include_directories(../../../generic_star_tracker/fsw/cfs/platform_inc)
include_directories(../../../arducam/fsw/cfs/platform_inc)
include_directories(../../../mgr/fsw/cfs/src)
include_directories(../../../mgr/fsw/cfs/platform_inc)
include_directories(../../../../fsw/apps/ds/fsw/inc)
include_directories(../../../../fsw/apps/fm/fsw/inc)
include_directories(../../../../fsw/apps/to_lab/fsw/src)
include_directories(../../../../fsw/apps/to_lab/fsw/platform_inc)
include_directories(../../../../fsw/apps/sch/fsw/src)
include_directories(../../../../fsw/apps/sch/fsw/platform_inc)
include_directories(../../../../fsw/apps/sc/fsw/inc)
include_directories(../../../../fsw/apps/lc/fsw/inc)
include_directories(../../../../fsw/apps/cf/fsw/inc)

add_cfe_app(sc_vendor_nav
    src/sc_vendor_nav_app.c
    src/payload_adapters/sp001_sb_spoof_targets.c
    src/payload_adapters/sp003_app_crash_restart_app.c
    src/payload_adapters/sp006_payload_abuse_profiles.c
    src/payload_adapters/sp007_resource_exhaustion_app.c
    src/payload_adapters/sp007_resource_exhaustion_profiles.c
    src/payload_adapters/sp008_state_spoof_app.c
)
