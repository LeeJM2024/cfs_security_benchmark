#include "sp003_app_crash_restart_app.h"

#include <stdlib.h>
#include <string.h>

#define SP003_EVENT_FLOOD_EID_BASE  100u
#define SP003_EVENT_FLOOD_EID_COUNT 128u

SP003_AppData_t SP003_AppData;

static int32 SP003_AppInit(void);
static void  SP003_ProcessPacket(void);
static void  SP003_ProcessGroundCommand(void);
static void  SP003_ProcessTelemetryRequest(void);
static void  SP003_ReportHousekeeping(void);
static void  SP003_ResetCounters(void);
static void  SP003_ResetPersistentState(void);
static void  SP003_LoadPersistentState(void);
static void  SP003_SavePersistentState(void);
static void  SP003_CopyStateToHk(void);
static void  SP003_EvaluateStartupFault(void);
static int32 SP003_RunProfile(const SP003_RunProfileCmd_t *Cmd);
static int32 SP003_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength);

int32 SP003_BenchmarkRunBounded(uint32 duration_ms)
{
    SP003_RunProfileCmd_t cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.ProfileId = SP003_PROFILE_EVENT_BURST;
    cmd.Arg1 = (int32)(duration_ms > SP003_MAX_BURST_COUNT ? SP003_MAX_BURST_COUNT : duration_ms);
    cmd.Arg2 = 1;
    return SP003_RunProfile(&cmd);
}
static int32 SP003_LookupTargetApp(const char *RequestedName, CFE_ES_AppId_t *AppIdPtr, char *ResolvedName,
                                   size_t ResolvedNameSize);
static int32 SP003_RestartTarget(const SP003_RunProfileCmd_t *Cmd);
static int32 SP003_DeleteTarget(const SP003_RunProfileCmd_t *Cmd);
static int32 SP003_ReloadTarget(const SP003_RunProfileCmd_t *Cmd);
static int32 SP003_RunRestartLoop(const char *TargetName, uint32 Count);
static int32 SP003_BusyLoop(uint32 DurationMs);
static int32 SP003_EventBurst(uint32 Count, uint32 DelayMs);
static int32 SP003_SyslogBurst(uint32 Count);
static int32 SP003_SyslogSentinel(uint32 Token);
static int32 SP003_ArmStartupFault(uint32 Count, uint32 Mode);
static void  SP003_TriggerSegfault(void);
static void  SP003_TriggerAbort(void);

void SP003_AppMain(void)
{
    int32 status = CFE_SUCCESS;

    CFE_ES_PerfLogEntry(SP003_APP_CRASH_RESTART_PERF_ID);

    status = SP003_AppInit();
    if (status != CFE_SUCCESS)
    {
        SP003_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SP003_AppData.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(SP003_APP_CRASH_RESTART_PERF_ID);

        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SP003_AppData.MsgPtr, SP003_AppData.CmdPipe,
                                      CFE_SB_PEND_FOREVER);

        CFE_ES_PerfLogEntry(SP003_APP_CRASH_RESTART_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SP003_ProcessPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SP003_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP003: SB pipe read error = %d",
                              (int)status);
            SP003_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }

        SP003_AppData.HkTelemetryPkt.Heartbeat++;
    }

    SP003_SavePersistentState();
    SP003_AppData.HkTelemetryPkt.LastRunStatus = SP003_AppData.RunStatus;

    CFE_ES_PerfLogExit(SP003_APP_CRASH_RESTART_PERF_ID);
    CFE_ES_ExitApp(SP003_AppData.RunStatus);
}

static int32 SP003_AppInit(void)
{
    int32 status;

    memset(&SP003_AppData, 0, sizeof(SP003_AppData));
    SP003_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP003: Error registering for event services: 0x%08X\n", (unsigned int)status);
        return status;
    }

    status = CFE_SB_CreatePipe(&SP003_AppData.CmdPipe, SP003_PIPE_DEPTH, "SP003_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP003_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP003: Error creating SB pipe, RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP003_CMD_MID), SP003_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP003_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP003: Error subscribing to SP003_CMD_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP003_REQ_HK_MID), SP003_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP003_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP003: Error subscribing to SP003_REQ_HK_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(SP003_AppData.HkTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(SP003_HK_TLM_MID),
                 SP003_HK_TLM_LEN);

    SP003_LoadPersistentState();
    SP003_AppData.State.BootCount++;
    SP003_SavePersistentState();
    SP003_ResetCounters();
    SP003_CopyStateToHk();

    CFE_EVS_SendEvent(SP003_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP003: app crash/restart pressure app initialized, boot=%lu",
                      (unsigned long)SP003_AppData.State.BootCount);

    SP003_EvaluateStartupFault();

    return CFE_SUCCESS;
}

static void SP003_ProcessPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(SP003_AppData.MsgPtr, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case SP003_CMD_MID:
            SP003_ProcessGroundCommand();
            break;

        case SP003_REQ_HK_MID:
            SP003_ProcessTelemetryRequest();
            break;

        default:
            SP003_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP003_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP003: received invalid MID 0x%04X",
                              (unsigned int)CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}

static void SP003_ProcessGroundCommand(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;
    int32             status      = CFE_SUCCESS;

    CFE_MSG_GetFcnCode(SP003_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        case SP003_NOOP_CC:
            if (SP003_VerifyCmdLength(SP003_AppData.MsgPtr, sizeof(SP003_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP003_AppData.HkTelemetryPkt.CommandCount++;
                CFE_EVS_SendEvent(SP003_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP003: NOOP command received");
            }
            break;

        case SP003_RESET_CC:
            if (SP003_VerifyCmdLength(SP003_AppData.MsgPtr, sizeof(SP003_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP003_ResetCounters();
                CFE_EVS_SendEvent(SP003_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP003: counters reset");
            }
            break;

        case SP003_RUN_PROFILE_CC:
            if (SP003_VerifyCmdLength(SP003_AppData.MsgPtr, sizeof(SP003_RunProfileCmd_t)) == CFE_SUCCESS)
            {
                const SP003_RunProfileCmd_t *Cmd = (const SP003_RunProfileCmd_t *)SP003_AppData.MsgPtr;

                SP003_AppData.HkTelemetryPkt.LastProfileId = Cmd->ProfileId;
                SP003_AppData.State.LastProfileId          = Cmd->ProfileId;
                SP003_AppData.State.LastStatus             = CFE_SUCCESS;
                SP003_SavePersistentState();

                status = SP003_RunProfile(Cmd);

                SP003_AppData.HkTelemetryPkt.CommandCount++;
                SP003_AppData.HkTelemetryPkt.LastStatus = status;
                SP003_AppData.State.LastStatus          = status;
                SP003_SavePersistentState();
                SP003_CopyStateToHk();

                if (status == CFE_SUCCESS)
                {
                    SP003_AppData.HkTelemetryPkt.ProfilesExecuted++;
                    CFE_EVS_SendEvent(SP003_PROFILE_INF_EID, CFE_EVS_EventType_INFORMATION,
                                      "SP003: profile %u executed", (unsigned int)Cmd->ProfileId);
                }
                else
                {
                    SP003_AppData.HkTelemetryPkt.CommandErrorCount++;
                    CFE_EVS_SendEvent(SP003_PROFILE_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "SP003: profile %u failed, RC=0x%08X", (unsigned int)Cmd->ProfileId,
                                      (unsigned int)status);
                }
            }
            break;

        default:
            SP003_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP003_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP003: invalid command code %u",
                              (unsigned int)CommandCode);
            break;
    }
}

static void SP003_ProcessTelemetryRequest(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(SP003_AppData.MsgPtr, &CommandCode);

    if (CommandCode == 0)
    {
        SP003_CopyStateToHk();
        SP003_ReportHousekeeping();
    }
    else
    {
        SP003_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(SP003_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP003: invalid HK request command code %u",
                          (unsigned int)CommandCode);
    }
}

static void SP003_ReportHousekeeping(void)
{
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SP003_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SP003_AppData.HkTelemetryPkt, true);
}

static void SP003_ResetCounters(void)
{
    SP003_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SP003_AppData.HkTelemetryPkt.CommandCount      = 0;
    SP003_AppData.HkTelemetryPkt.LastProfileId     = 0;
    SP003_AppData.HkTelemetryPkt.LastStatus        = 0;
    SP003_AppData.HkTelemetryPkt.ProfilesExecuted  = 0;
}

static void SP003_ResetPersistentState(void)
{
    uint32 old_boot_count = SP003_AppData.State.BootCount;

    memset(&SP003_AppData.State, 0, sizeof(SP003_AppData.State));
    SP003_AppData.State.Magic     = SP003_STATE_MAGIC;
    SP003_AppData.State.Version   = SP003_STATE_VERSION;
    SP003_AppData.State.BootCount = old_boot_count;
    SP003_SavePersistentState();
    SP003_CopyStateToHk();
}

static void SP003_LoadPersistentState(void)
{
    int32     status;
    int32     size_read;
    osal_id_t fd;

    memset(&SP003_AppData.State, 0, sizeof(SP003_AppData.State));

    status = OS_OpenCreate(&fd, SP003_STATE_FILE, OS_FILE_FLAG_NONE, OS_READ_ONLY);
    if (status == OS_SUCCESS)
    {
        size_read = OS_TimedRead(fd, &SP003_AppData.State, sizeof(SP003_AppData.State), 500); // 一共读了多少字节
        OS_close(fd);

        if ((size_read == sizeof(SP003_AppData.State)) && (SP003_AppData.State.Magic == SP003_STATE_MAGIC) &&
            (SP003_AppData.State.Version == SP003_STATE_VERSION))
        {
            return;
        }

        CFE_EVS_SendEvent(SP003_RUNTIME_WARN_EID, CFE_EVS_EventType_INFORMATION,
                          "SP003: persistent state invalid, recreating");
    }

    SP003_AppData.State.Magic   = SP003_STATE_MAGIC;
    SP003_AppData.State.Version = SP003_STATE_VERSION;
}

static void SP003_SavePersistentState(void)
{
    int32     status;
    int32     bytes_written;
    osal_id_t fd;

    SP003_AppData.State.Magic   = SP003_STATE_MAGIC;
    SP003_AppData.State.Version = SP003_STATE_VERSION;

    status = OS_OpenCreate(&fd, SP003_STATE_FILE, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_READ_WRITE);
    if (status != OS_SUCCESS)
    {
        CFE_EVS_SendEvent(SP003_RUNTIME_WARN_EID, CFE_EVS_EventType_INFORMATION,
                          "SP003: unable to open persistent state file, RC=0x%08X", (unsigned int)status);
        return;
    }

    bytes_written = OS_write(fd, &SP003_AppData.State, sizeof(SP003_AppData.State)); // 一共写了多少字节
    if (bytes_written != sizeof(SP003_AppData.State))
    {
        CFE_EVS_SendEvent(SP003_RUNTIME_WARN_EID, CFE_EVS_EventType_INFORMATION,
                          "SP003: persistent state short write, RC=%d", (int)bytes_written);
    }

    OS_close(fd);
}

static void SP003_CopyStateToHk(void)
{
    SP003_AppData.HkTelemetryPkt.BootCount             = SP003_AppData.State.BootCount;
    SP003_AppData.HkTelemetryPkt.SelfExitCount         = SP003_AppData.State.SelfExitCount;
    SP003_AppData.HkTelemetryPkt.CrashRequestCount     = SP003_AppData.State.CrashRequestCount;
    SP003_AppData.HkTelemetryPkt.AbortRequestCount     = SP003_AppData.State.AbortRequestCount;
    SP003_AppData.HkTelemetryPkt.RestartApiCount       = SP003_AppData.State.RestartApiCount;
    SP003_AppData.HkTelemetryPkt.DeleteApiCount        = SP003_AppData.State.DeleteApiCount;
    SP003_AppData.HkTelemetryPkt.ReloadApiCount        = SP003_AppData.State.ReloadApiCount;
    SP003_AppData.HkTelemetryPkt.BusyLoopCount         = SP003_AppData.State.BusyLoopCount;
    SP003_AppData.HkTelemetryPkt.EventBurstCount       = SP003_AppData.State.EventBurstCount;
    SP003_AppData.HkTelemetryPkt.SyslogBurstCount      = SP003_AppData.State.SyslogBurstCount;
    SP003_AppData.HkTelemetryPkt.StartupFaultRemaining = SP003_AppData.State.StartupFaultRemaining;
    SP003_AppData.HkTelemetryPkt.StartupFaultMode      = SP003_AppData.State.StartupFaultMode;
    SP003_AppData.HkTelemetryPkt.LastRunStatus         = SP003_AppData.RunStatus;
}

static void SP003_EvaluateStartupFault(void)
{
    uint32 mode;

    if (SP003_AppData.State.StartupFaultRemaining == 0)
    {
        return;
    }

    mode = SP003_AppData.State.StartupFaultMode;
    SP003_AppData.State.StartupFaultRemaining--;
    SP003_SavePersistentState();
    SP003_CopyStateToHk();

    CFE_EVS_SendEvent(SP003_STARTUP_FAULT_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP003: startup fault mode=%lu remaining=%lu", (unsigned long)mode,
                      (unsigned long)SP003_AppData.State.StartupFaultRemaining);

    OS_TaskDelay(100);

    switch (mode)
    {
        case SP003_STARTUP_FAULT_EXIT_ERROR:
            SP003_AppData.State.SelfExitCount++;
            SP003_SavePersistentState();
            SP003_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
            break;

        case SP003_STARTUP_FAULT_SEGFAULT:
            SP003_AppData.State.CrashRequestCount++;
            SP003_SavePersistentState();
            SP003_TriggerSegfault();
            break;

        case SP003_STARTUP_FAULT_ABORT:
            SP003_AppData.State.AbortRequestCount++;
            SP003_SavePersistentState();
            SP003_TriggerAbort();
            break;

        case SP003_STARTUP_FAULT_RESTART_SELF:
            SP003_RunRestartLoop(SP003_APP_NAME, 1);
            break;

        default:
            SP003_AppData.State.StartupFaultMode = SP003_STARTUP_FAULT_NONE;
            SP003_SavePersistentState();
            break;
    }
}

static int32 SP003_RunProfile(const SP003_RunProfileCmd_t *Cmd)
{
    uint32 count;
    uint32 mode;

    switch (Cmd->ProfileId)
    {
        case SP003_PROFILE_SELF_EXIT_NORMAL: // 让自己正常退出
            SP003_AppData.State.SelfExitCount++;
            SP003_AppData.RunStatus = CFE_ES_RunStatus_APP_EXIT;
            return CFE_SUCCESS;

        case SP003_PROFILE_SELF_EXIT_ERROR: // 让自己错误退出
            SP003_AppData.State.SelfExitCount++;
            SP003_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
            return CFE_SUCCESS;

        case SP003_PROFILE_SELF_RESTART_API:
            return SP003_RunRestartLoop(SP003_APP_NAME, 1);

        case SP003_PROFILE_RESTART_TARGET_API: // 调用CFE_ES_RestartApp, 可能重启其他app
            return SP003_RestartTarget(Cmd);

        case SP003_PROFILE_DELETE_TARGET_API: // 同理，可能删除其他app
            return SP003_DeleteTarget(Cmd);

        case SP003_PROFILE_RELOAD_TARGET_API: // 同理，可能重载其他app
            return SP003_ReloadTarget(Cmd);

        case SP003_PROFILE_BUSY_LOOP_MS: // CPU忙等压力
            count = (Cmd->Arg1 <= 0) ? 1000u : (uint32)Cmd->Arg1;
            return SP003_BusyLoop(count);

        case SP003_PROFILE_EVENT_BURST: // EVS event 洪泛
            count = (Cmd->Arg1 <= 0) ? 20u : (uint32)Cmd->Arg1;
            return SP003_EventBurst(count, (Cmd->Arg2 <= 0) ? 0u : (uint32)Cmd->Arg2);
 
        case SP003_PROFILE_SYSLOG_BURST: // ES syslog 洪泛
            count = (Cmd->Arg1 <= 0) ? 20u : (uint32)Cmd->Arg1;
            return SP003_SyslogBurst(count);

        case SP003_PROFILE_SYSLOG_SENTINEL:
            return SP003_SyslogSentinel((Cmd->Arg1 <= 0) ? 1u : (uint32)Cmd->Arg1);

        case SP003_PROFILE_ARM_STARTUP_FAULT_LOOP: // 模拟app每次启动就故障
            count = (Cmd->Arg1 <= 0) ? 1u : (uint32)Cmd->Arg1;
            mode  = (Cmd->Arg2 <= 0) ? SP003_STARTUP_FAULT_EXIT_ERROR : (uint32)Cmd->Arg2;
            return SP003_ArmStartupFault(count, mode);

        case SP003_PROFILE_DISARM_STARTUP_FAULT:
            SP003_AppData.State.StartupFaultRemaining = 0;
            SP003_AppData.State.StartupFaultMode      = SP003_STARTUP_FAULT_NONE;
            return CFE_SUCCESS;

        case SP003_PROFILE_SEGFAULT:
            SP003_AppData.State.CrashRequestCount++;
            SP003_SavePersistentState();
            SP003_TriggerSegfault();
            return CFE_SUCCESS;

        case SP003_PROFILE_ABORT:
            SP003_AppData.State.AbortRequestCount++;
            SP003_SavePersistentState();
            SP003_TriggerAbort();
            return CFE_SUCCESS;

        case SP003_PROFILE_CLEAR_PERSISTENT_STATE:
            SP003_ResetPersistentState();
            return CFE_SUCCESS;

        default:
            return CFE_STATUS_BAD_COMMAND_CODE;
    }
}

static int32 SP003_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength)
{
    size_t            ActualLength = 0;
    CFE_SB_MsgId_t    MsgId        = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode  = 0;

    CFE_MSG_GetSize(Msg, &ActualLength);

    if (ActualLength == ExpectedLength)
    {
        return CFE_SUCCESS;
    }

    CFE_MSG_GetMsgId(Msg, &MsgId);
    CFE_MSG_GetFcnCode(Msg, &CommandCode);

    SP003_AppData.HkTelemetryPkt.CommandErrorCount++;

    CFE_EVS_SendEvent(SP003_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                      "SP003: invalid length MID=0x%04X CC=%u Len=%lu Expected=%u",
                      (unsigned int)CFE_SB_MsgIdToValue(MsgId), (unsigned int)CommandCode,
                      (unsigned long)ActualLength, (unsigned int)ExpectedLength);

    return CFE_STATUS_WRONG_MSG_LENGTH;
}

static int32 SP003_LookupTargetApp(const char *RequestedName, CFE_ES_AppId_t *AppIdPtr, char *ResolvedName,
                                   size_t ResolvedNameSize)
{
    if ((AppIdPtr == NULL) || (ResolvedName == NULL) || (ResolvedNameSize == 0))
    {
        return CFE_ES_BAD_ARGUMENT;
    }

    memset(ResolvedName, 0, ResolvedNameSize);

    if ((RequestedName == NULL) || (RequestedName[0] == '\0'))
    {
        strncpy(ResolvedName, SP003_APP_NAME, ResolvedNameSize - 1);
    }
    else
    {
        strncpy(ResolvedName, RequestedName, ResolvedNameSize - 1);
        ResolvedName[ResolvedNameSize - 1] = '\0';
    }

    return CFE_ES_GetAppIDByName(AppIdPtr, ResolvedName);
}

static int32 SP003_RestartTarget(const SP003_RunProfileCmd_t *Cmd)
{
    uint32 count = (Cmd->Arg1 <= 0) ? 1u : (uint32)Cmd->Arg1;

    return SP003_RunRestartLoop(Cmd->TargetApp, count);
}

static int32 SP003_DeleteTarget(const SP003_RunProfileCmd_t *Cmd)
{
    CFE_ES_AppId_t app_id;
    char           target_name[SP003_TARGET_APP_NAME_LEN];
    int32          status;

    status = SP003_LookupTargetApp(Cmd->TargetApp, &app_id, target_name, sizeof(target_name));
    if (status != CFE_SUCCESS)
    {
        return status;
    }

    SP003_AppData.State.DeleteApiCount++;
    status = CFE_ES_DeleteApp(app_id);
    CFE_EVS_SendEvent(SP003_PRESSURE_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP003: CFE_ES_DeleteApp target=%s RC=0x%08X", target_name, (unsigned int)status);

    return status;
}

static int32 SP003_ReloadTarget(const SP003_RunProfileCmd_t *Cmd)
{
    CFE_ES_AppId_t app_id;
    char           target_name[SP003_TARGET_APP_NAME_LEN];
    char           reload_path[SP003_RELOAD_PATH_LEN];
    int32          status;

    memset(reload_path, 0, sizeof(reload_path));
    strncpy(reload_path, Cmd->ReloadPath, sizeof(reload_path) - 1);

    if (reload_path[0] == '\0')
    {
        return CFE_ES_BAD_ARGUMENT;
    }

    status = SP003_LookupTargetApp(Cmd->TargetApp, &app_id, target_name, sizeof(target_name));
    if (status != CFE_SUCCESS)
    {
        return status;
    }

    SP003_AppData.State.ReloadApiCount++;
    status = CFE_ES_ReloadApp(app_id, reload_path);
    CFE_EVS_SendEvent(SP003_PRESSURE_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP003: CFE_ES_ReloadApp target=%s file=%s RC=0x%08X", target_name, reload_path,
                      (unsigned int)status);

    return status;
}

static int32 SP003_RunRestartLoop(const char *TargetName, uint32 Count)
{
    CFE_ES_AppId_t app_id;
    char           target_name[SP003_TARGET_APP_NAME_LEN];
    uint32         i;
    int32          status      = CFE_SUCCESS;
    int32          last_status = CFE_SUCCESS;

    if (Count > SP003_MAX_PROFILE_LOOPS)
    {
        Count = SP003_MAX_PROFILE_LOOPS;
    }

    status = SP003_LookupTargetApp(TargetName, &app_id, target_name, sizeof(target_name));
    if (status != CFE_SUCCESS)
    {
        return status;
    }

    for (i = 0; i < Count; i++)
    {
        SP003_AppData.State.RestartApiCount++;
        last_status = CFE_ES_RestartApp(app_id);
        CFE_EVS_SendEvent(SP003_PRESSURE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "SP003: CFE_ES_RestartApp target=%s iter=%lu/%lu RC=0x%08X", target_name,
                          (unsigned long)(i + 1), (unsigned long)Count, (unsigned int)last_status);

        if (last_status != CFE_SUCCESS)
        {
            return last_status;
        }
    }

    return last_status;
}

static int32 SP003_BusyLoop(uint32 DurationMs)
{
    uint32        elapsed;
    volatile uint32 sink = 0;

    if (DurationMs > SP003_MAX_BUSY_MS)
    {
        DurationMs = SP003_MAX_BUSY_MS;
    }

    SP003_AppData.State.BusyLoopCount++;
    CFE_EVS_SendEvent(SP003_PRESSURE_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP003: busy loop for %lu ms", (unsigned long)DurationMs);

    for (elapsed = 0; elapsed < DurationMs; elapsed++)
    {
        uint32 inner;

        for (inner = 0; inner < 50000u; inner++)
        {
            sink += (inner ^ elapsed);
        }
    }

    (void)sink;
    return CFE_SUCCESS;
}

static int32 SP003_EventBurst(uint32 Count, uint32 DelayMs)
{
    uint32 i;
    uint16 event_id;

    if (Count > SP003_MAX_BURST_COUNT)
    {
        Count = SP003_MAX_BURST_COUNT;
    }
    if (DelayMs > 50u)
    {
        DelayMs = 50u;
    }

    SP003_AppData.State.EventBurstCount++;

    for (i = 0; i < Count; i++)
    {
        event_id = (uint16)(SP003_EVENT_FLOOD_EID_BASE + (i % SP003_EVENT_FLOOD_EID_COUNT));
        CFE_EVS_SendEvent(event_id, CFE_EVS_EventType_INFORMATION,
                          "SP003: EVS burst event %lu/%lu", (unsigned long)(i + 1), (unsigned long)Count);
        if (DelayMs > 0u)
        {
            OS_TaskDelay(DelayMs);
        }
    }

    return CFE_SUCCESS;
}

static int32 SP003_SyslogBurst(uint32 Count)
{
    uint32 i;

    if (Count > SP003_MAX_BURST_COUNT)
    {
        Count = SP003_MAX_BURST_COUNT;
    }

    SP003_AppData.State.SyslogBurstCount++;

    for (i = 0; i < Count; i++)
    {
        CFE_ES_WriteToSysLog("SP003: syslog pressure entry %lu/%lu\n", (unsigned long)(i + 1),
                             (unsigned long)Count);
    }

    return CFE_SUCCESS;
}

static int32 SP003_SyslogSentinel(uint32 Token)
{
    CFE_ES_WriteToSysLog("SP003: syslog sentinel token %lu\n", (unsigned long)Token);
    return CFE_SUCCESS;
}

// 该函数不是立即crash，而是设置一个“下次启动时触发”的故障，在下次的SP003_AppInit()，会调用SP003_EvaluateStartupFault();
static int32 SP003_ArmStartupFault(uint32 Count, uint32 Mode)
{
    if (Count > SP003_MAX_PROFILE_LOOPS)
    {
        Count = SP003_MAX_PROFILE_LOOPS;
    }

    switch (Mode)
    {
        case SP003_STARTUP_FAULT_EXIT_ERROR:
        case SP003_STARTUP_FAULT_SEGFAULT:
        case SP003_STARTUP_FAULT_ABORT:
        case SP003_STARTUP_FAULT_RESTART_SELF:
            SP003_AppData.State.StartupFaultRemaining = Count;
            SP003_AppData.State.StartupFaultMode      = Mode;
            CFE_EVS_SendEvent(SP003_PROFILE_INF_EID, CFE_EVS_EventType_INFORMATION,
                              "SP003: armed startup fault mode=%lu count=%lu", (unsigned long)Mode,
                              (unsigned long)Count);
            return CFE_SUCCESS;

        default:
            return CFE_STATUS_BAD_COMMAND_CODE;
    }
}

static void SP003_TriggerSegfault(void)
{
    volatile uint32 *bad_ptr = (volatile uint32 *)0;

    CFE_ES_WriteToSysLog("SP003: triggering deliberate NULL write fault\n");
    *bad_ptr = 0x53503033u;
}

static void SP003_TriggerAbort(void)
{
    CFE_ES_WriteToSysLog("SP003: triggering deliberate abort()\n");
    abort();
}
