#ifndef _SP003_APP_CRASH_RESTART_MSG_H_
#define _SP003_APP_CRASH_RESTART_MSG_H_

#include "cfe.h"

#define SP003_NOOP_CC        0
#define SP003_RESET_CC       1
#define SP003_RUN_PROFILE_CC 2

#define SP003_TARGET_APP_NAME_LEN 32
#define SP003_RELOAD_PATH_LEN     64

#define SP003_PROFILE_SELF_EXIT_NORMAL       1
#define SP003_PROFILE_SELF_EXIT_ERROR        2
#define SP003_PROFILE_SELF_RESTART_API       3
#define SP003_PROFILE_RESTART_TARGET_API     10
#define SP003_PROFILE_DELETE_TARGET_API      11
#define SP003_PROFILE_RELOAD_TARGET_API      12
#define SP003_PROFILE_BUSY_LOOP_MS           20
#define SP003_PROFILE_EVENT_BURST            21
#define SP003_PROFILE_SYSLOG_BURST           22
#define SP003_PROFILE_SYSLOG_SENTINEL        23
#define SP003_PROFILE_ARM_STARTUP_FAULT_LOOP 30
#define SP003_PROFILE_DISARM_STARTUP_FAULT   31
#define SP003_PROFILE_SEGFAULT               40
#define SP003_PROFILE_ABORT                  41
#define SP003_PROFILE_CLEAR_PERSISTENT_STATE 50

#define SP003_STARTUP_FAULT_NONE         0
#define SP003_STARTUP_FAULT_EXIT_ERROR   1
#define SP003_STARTUP_FAULT_SEGFAULT     2
#define SP003_STARTUP_FAULT_ABORT        3
#define SP003_STARTUP_FAULT_RESTART_SELF 4

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SP003_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint16                  ProfileId;
    uint16                  Flags;
    int32                   Arg1;
    int32                   Arg2;
    int32                   Arg3;
    int32                   Arg4;
    char                    TargetApp[SP003_TARGET_APP_NAME_LEN];
    char                    ReloadPath[SP003_RELOAD_PATH_LEN];
} __attribute__((packed)) SP003_RunProfileCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint16                    LastProfileId;
    int32                     LastStatus;
    uint32                    ProfilesExecuted;
    uint32                    BootCount;
    uint32                    Heartbeat;
    uint32                    SelfExitCount;
    uint32                    CrashRequestCount;
    uint32                    AbortRequestCount;
    uint32                    RestartApiCount;
    uint32                    DeleteApiCount;
    uint32                    ReloadApiCount;
    uint32                    BusyLoopCount;
    uint32                    EventBurstCount;
    uint32                    SyslogBurstCount;
    uint32                    StartupFaultRemaining;
    uint32                    StartupFaultMode;
    uint32                    LastRunStatus;
} __attribute__((packed)) SP003_HkTlm_t;

#define SP003_HK_TLM_LEN sizeof(SP003_HkTlm_t)

#endif
