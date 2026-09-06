#ifndef _SP003_APP_CRASH_RESTART_APP_H_
#define _SP003_APP_CRASH_RESTART_APP_H_

#include "cfe.h"

#include "sp003_app_crash_restart_events.h"
#include "sp003_app_crash_restart_msg.h"
#include "sp003_app_crash_restart_msgids.h"
#include "sp003_app_crash_restart_perfids.h"

#define SP003_APP_NAME          "SP003"
#define SP003_PIPE_DEPTH        16
#define SP003_STATE_FILE        "/cf/sp003_state.dat" // Persistent state used to preserve SP003 evidence across app restarts
#define SP003_STATE_MAGIC       0x53503033u
#define SP003_STATE_VERSION     1u
#define SP003_MAX_PROFILE_LOOPS 50u
#define SP003_MAX_BUSY_MS       10000u
#define SP003_MAX_BURST_COUNT   200u

typedef struct
{
    uint32 Magic;
    uint32 Version;
    uint32 BootCount;
    uint32 SelfExitCount;
    uint32 CrashRequestCount;
    uint32 AbortRequestCount;
    uint32 RestartApiCount;
    uint32 DeleteApiCount;
    uint32 ReloadApiCount;
    uint32 BusyLoopCount;
    uint32 EventBurstCount;
    uint32 SyslogBurstCount;
    uint32 StartupFaultRemaining;
    uint32 StartupFaultMode;
    uint32 LastProfileId;
    int32  LastStatus;
} SP003_PersistentState_t;

typedef struct
{
    CFE_SB_PipeId_t          CmdPipe;
    CFE_MSG_Message_t        *MsgPtr;
    uint32                   RunStatus;
    SP003_HkTlm_t            HkTelemetryPkt;
    SP003_PersistentState_t  State;
} SP003_AppData_t;

extern SP003_AppData_t SP003_AppData;

void SP003_AppMain(void);

/* Embedded-carrier entry point used by the supply-chain vendor adapter. */
int32 SP003_BenchmarkRunBounded(uint32 duration_ms);

#endif
