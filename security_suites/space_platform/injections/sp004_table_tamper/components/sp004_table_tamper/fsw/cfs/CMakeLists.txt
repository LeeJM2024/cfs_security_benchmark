cmake_minimum_required(VERSION 2.6.4)
project(SP004_TABLE_TAMPER C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)
include_directories(${APPLICATION_PLATFORM_INC_LIST})
include_directories(${MISSION_SOURCE_DIR}/apps/to/fsw/examples/${TO_TRANSPORT})
include_directories(${MISSION_SOURCE_DIR}/apps/to/fsw/src)
include_directories(${MISSION_SOURCE_DIR}/apps/to/fsw/tables)
include_directories(${MISSION_SOURCE_DIR}/apps/to/fsw/mission_inc)
include_directories(${MISSION_SOURCE_DIR}/apps/to_lab/fsw/platform_inc)

add_cfe_app(sp004_tbl_tamper
    src/sp004_table_tamper_app.c
    src/sp004_table_tamper_profiles.c
)

set(TGTLIST_sp004_tbl_tamper ${APP_DYNAMIC_TARGET_LIST})
add_cfe_tables(sp004_tbl_tamper
    tables/sp004_fm_bad.c
    tables/sp004_ds_file_bad.c
    tables/sp004_ds_filter_bad.c
    tables/sp004_sch_sched_bad.c
    tables/sp004_sch_msg_bad.c
    tables/sp004_lc_wdt_bad.c
    tables/sp004_lc_adt_bad.c
    tables/sp004_cf_config_bad.c
    tables/sp004_to_config_bad.c
    tables/sp004_sc_rts001_bad.c
    tables/sp004_sc_ats1_bad.c
    tables/sp004_sbn_conf_bad.c
)
