#ifndef _SP004_TABLE_TAMPER_MSG_H_
#define _SP004_TABLE_TAMPER_MSG_H_

#include "cfe.h"

#define SP004_NOOP_CC        0
#define SP004_RESET_CC       1
#define SP004_RUN_PROFILE_CC 2

#define SP004_PROFILE_TBL_LOAD                   1
#define SP004_PROFILE_TBL_VALIDATE_INACTIVE      2
#define SP004_PROFILE_TBL_VALIDATE_ACTIVE        3
#define SP004_PROFILE_TBL_ACTIVATE               4
#define SP004_PROFILE_TBL_DUMP_INACTIVE          5
#define SP004_PROFILE_TBL_DUMP_ACTIVE            6
#define SP004_PROFILE_TBL_SEND_REGISTRY          7
#define SP004_PROFILE_TBL_DUMP_REGISTRY          8
#define SP004_PROFILE_TBL_ABORT_LOAD             9
#define SP004_PROFILE_LOAD_VALIDATE_ACTIVATE     20
#define SP004_PROFILE_LOAD_VALIDATE_ACTIVATE_DUMP 21
#define SP004_PROFILE_RESTORE_VALIDATE_ACTIVATE  30
#define SP004_PROFILE_RESTORE_VALIDATE_ACTIVATE_DUMP 31

#define SP004_TARGET_CUSTOM       0
#define SP004_TARGET_DS_FILE      1
#define SP004_TARGET_DS_FILTER    2
#define SP004_TARGET_SCH_SCHED    10
#define SP004_TARGET_SCH_MSG      11
#define SP004_TARGET_LC_WDT       20
#define SP004_TARGET_LC_ADT       21
#define SP004_TARGET_FM_MONITOR   30
#define SP004_TARGET_CF_CONFIG    40
#define SP004_TARGET_TO_CONFIG    50
#define SP004_TARGET_SC_RTS001    60
#define SP004_TARGET_SC_ATS1      61
#define SP004_TARGET_SBN_CONF     70

#define SP004_FLAG_VALIDATE_AFTER_LOAD 0x0001u
#define SP004_FLAG_ACTIVATE_AFTER_LOAD 0x0002u
#define SP004_FLAG_DUMP_AFTER_ACTIVATE 0x0004u
#define SP004_FLAG_USE_RESTORE_FILE    0x0008u

#define SP004_TABLE_NAME_LEN 64
#define SP004_PATH_LEN       64

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SP004_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint16                  ProfileId;
    uint16                  Flags;
    uint16                  TargetId;
    uint16                  ActiveTableFlag;
    int32                   StepDelayMs;
    int32                   Arg2;
    int32                   Arg3;
    int32                   Arg4;
    char                    TableName[SP004_TABLE_NAME_LEN];
    char                    LoadFilename[SP004_PATH_LEN];
    char                    RestoreFilename[SP004_PATH_LEN];
    char                    DumpFilename[SP004_PATH_LEN];
} __attribute__((packed)) SP004_RunProfileCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint16                    LastProfileId;
    uint16                    LastTargetId;
    uint16                    LastActionMask;
    int32                     LastStatus;
    int32                     LastTblStatus;
    uint32                    ProfilesExecuted;
    uint32                    TblLoadCount;
    uint32                    TblValidateCount;
    uint32                    TblActivateCount;
    uint32                    TblDumpCount;
    uint32                    TblRegistryCount;
    uint32                    TblAbortCount;
    uint32                    RestoreCount;
    uint32                    TxErrorCount;
    char                      LastTableName[SP004_TABLE_NAME_LEN];
    char                      LastLoadFilename[SP004_PATH_LEN];
    char                      LastDumpFilename[SP004_PATH_LEN];
} __attribute__((packed)) SP004_HkTlm_t;

#define SP004_HK_TLM_LEN sizeof(SP004_HkTlm_t)

#endif
