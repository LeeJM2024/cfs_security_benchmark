#ifndef _SP001_SB_SPOOF_MSG_H_
#define _SP001_SB_SPOOF_MSG_H_

#include "cfe.h"

#define SP001_NOOP_CC        0
#define SP001_RESET_CC       1
#define SP001_RUN_PROFILE_CC 2

#define SP001_PROFILE_ADCS_SET_MODE            1
#define SP001_PROFILE_ADCS_MOMENTUM_MANAGEMENT 2
#define SP001_PROFILE_TORQUER_ENABLE           10
#define SP001_PROFILE_TORQUER_DISABLE          11
#define SP001_PROFILE_TORQUER_PERCENT_ON       12
#define SP001_PROFILE_TORQUER_ALL_PERCENT_ON   13
#define SP001_PROFILE_RW_SET_TORQUE            20
#define SP001_PROFILE_RW_ENABLE                21
#define SP001_PROFILE_RW_DISABLE               22
#define SP001_PROFILE_EPS_SWITCH               30
#define SP001_PROFILE_DS_SET_APP_STATE         40
#define SP001_PROFILE_DS_SET_DEST_STATE        41
#define SP001_PROFILE_FM_CREATE_DIR            50
#define SP001_PROFILE_FM_DELETE_FILE           51
#define SP001_PROFILE_FM_DELETE_ALL            52
#define SP001_PROFILE_FM_SET_FILE_PERM         53
#define SP001_PROFILE_FM_DELETE_DIR            54
#define SP001_PROFILE_THRUSTER_ENABLE          60
#define SP001_PROFILE_THRUSTER_DISABLE         61
#define SP001_PROFILE_THRUSTER_PERCENTAGE      62
#define SP001_PROFILE_RADIO_CONFIG             70
#define SP001_PROFILE_RADIO_PROXIMITY          71
#define SP001_PROFILE_NOVATEL_ENABLE           80
#define SP001_PROFILE_NOVATEL_DISABLE          81
#define SP001_PROFILE_NOVATEL_LOG              82
#define SP001_PROFILE_NOVATEL_UNLOG            83
#define SP001_PROFILE_NOVATEL_UNLOGALL         84
#define SP001_PROFILE_NOVATEL_SERIALCONFIG     85
#define SP001_PROFILE_IMU_ENABLE               90
#define SP001_PROFILE_IMU_DISABLE              91
#define SP001_PROFILE_IMU_CONFIG               92
#define SP001_PROFILE_MAG_ENABLE               100
#define SP001_PROFILE_MAG_DISABLE              101
#define SP001_PROFILE_CSS_ENABLE               110
#define SP001_PROFILE_CSS_DISABLE              111
#define SP001_PROFILE_FSS_ENABLE               120
#define SP001_PROFILE_FSS_DISABLE              121
#define SP001_PROFILE_STAR_TRACKER_ENABLE      130
#define SP001_PROFILE_STAR_TRACKER_DISABLE     131
#define SP001_PROFILE_STAR_TRACKER_CONFIG      132
#define SP001_PROFILE_TO_LAB_OUTPUT_ENABLE     200
#define SP001_PROFILE_TO_LAB_REMOVE_PKT        201
#define SP001_PROFILE_TO_LAB_REMOVE_ALL        202
#define SP001_PROFILE_SCH_ENABLE_ENTRY         210
#define SP001_PROFILE_SCH_DISABLE_ENTRY        211
#define SP001_PROFILE_SCH_ENABLE_GROUP         212
#define SP001_PROFILE_SCH_DISABLE_GROUP        213
#define SP001_PROFILE_SC_START_RTS             220
#define SP001_PROFILE_SC_STOP_RTS              221
#define SP001_PROFILE_SC_ENABLE_RTS            222
#define SP001_PROFILE_SC_DISABLE_RTS           223
#define SP001_PROFILE_LC_SET_STATE             230
#define SP001_PROFILE_LC_SET_AP_STATE          231
#define SP001_PROFILE_CF_FREEZE                240
#define SP001_PROFILE_CF_THAW                  241
#define SP001_PROFILE_CF_ENABLE_ENGINE         242
#define SP001_PROFILE_CF_DISABLE_ENGINE        243
#define SP001_PROFILE_TBL_LOAD                 250
#define SP001_PROFILE_TBL_VALIDATE             251
#define SP001_PROFILE_TBL_ACTIVATE             252
#define SP001_PROFILE_ES_STOP_APP              260
#define SP001_PROFILE_ES_RESTART_APP           261

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SP001_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint16                  ProfileId;
    uint16                  Flags;
    int32                   Arg1;
    int32                   Arg2;
    int32                   Arg3;
    int32                   Arg4;
} __attribute__((packed)) SP001_RunProfileCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint16                    LastProfileId;
    int32                     LastStatus;
    uint32                    ProfilesExecuted;
} __attribute__((packed)) SP001_HkTlm_t;

#define SP001_HK_TLM_LEN sizeof(SP001_HkTlm_t)

#endif
