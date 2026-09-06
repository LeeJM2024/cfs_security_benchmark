#include "sp007_resource_exhaustion_app.h"
#include "sp007_resource_exhaustion_profiles.h"

#include <string.h>

SP007_AppData_t SP007_AppData;

static int32 SP007_AppInit(void);
static void  SP007_ProcessPacket(void);
static void  SP007_ProcessGroundCommand(void);
static void  SP007_ProcessTelemetryRequest(void);
static void  SP007_ReportHousekeeping(void);
static void  SP007_ResetCounters(void);
static int32 SP007_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength);

void SP007_AppMain(void)
{
    int32 status = CFE_SUCCESS;

    CFE_ES_PerfLogEntry(SP007_RESOURCE_EXHAUSTION_PERF_ID);

    status = SP007_AppInit();
    if (status != CFE_SUCCESS)
    {
        SP007_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SP007_AppData.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(SP007_RESOURCE_EXHAUSTION_PERF_ID);

        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SP007_AppData.MsgPtr, SP007_AppData.CmdPipe,
                                      CFE_SB_PEND_FOREVER);

        CFE_ES_PerfLogEntry(SP007_RESOURCE_EXHAUSTION_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SP007_ProcessPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SP007_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP007: SB pipe read error = 0x%08X",
                              (unsigned int)status);
            SP007_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    SP007_StopProfile();
    SP007_CleanupResources();

    CFE_ES_PerfLogExit(SP007_RESOURCE_EXHAUSTION_PERF_ID);
    CFE_ES_ExitApp(SP007_AppData.RunStatus);
}

static int32 SP007_AppInit(void)
{
    int32 status;

    memset(&SP007_AppData, 0, sizeof(SP007_AppData));
    SP007_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;
    SP007_ResetProfileState();

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP007: Error registering for event services: 0x%08X\n", (unsigned int)status);
        return status;
    }

    status = CFE_SB_CreatePipe(&SP007_AppData.CmdPipe, SP007_PIPE_DEPTH, "SP007_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP007_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP007: Error creating SB pipe, RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP007_CMD_MID), SP007_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP007_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP007: Error subscribing to SP007_CMD_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP007_REQ_HK_MID), SP007_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP007_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP007: Error subscribing to SP007_REQ_HK_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(SP007_AppData.HkTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(SP007_HK_TLM_MID),
                 SP007_HK_TLM_LEN);
    CFE_MSG_Init(CFE_MSG_PTR(SP007_AppData.FloodTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(SP007_FLOOD_TLM_MID),
                 SP007_FLOOD_TLM_LEN);

    SP007_ResetCounters();

    CFE_EVS_SendEvent(SP007_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP007: resource exhaustion app initialized");

    return CFE_SUCCESS;
}

static void SP007_ProcessPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(SP007_AppData.MsgPtr, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case SP007_CMD_MID:
            SP007_ProcessGroundCommand();
            break;

        case SP007_REQ_HK_MID:
            SP007_ProcessTelemetryRequest();
            break;

        default:
            SP007_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP007_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP007: received invalid MID 0x%04X",
                              (unsigned int)CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}

static void SP007_ProcessGroundCommand(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;
    int32             status      = CFE_SUCCESS;

    CFE_MSG_GetFcnCode(SP007_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        case SP007_NOOP_CC:
            if (SP007_VerifyCmdLength(SP007_AppData.MsgPtr, sizeof(SP007_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP007_AppData.HkTelemetryPkt.CommandCount++;
                CFE_EVS_SendEvent(SP007_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP007: NOOP command received");
            }
            break;

        case SP007_RESET_CC:
            if (SP007_VerifyCmdLength(SP007_AppData.MsgPtr, sizeof(SP007_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP007_ResetCounters();
                CFE_EVS_SendEvent(SP007_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP007: counters reset");
            }
            break;

        case SP007_START_PROFILE_CC:
            if (SP007_VerifyCmdLength(SP007_AppData.MsgPtr, sizeof(SP007_StartProfileCmd_t)) == CFE_SUCCESS)
            {
                const SP007_StartProfileCmd_t *Cmd = (const SP007_StartProfileCmd_t *)SP007_AppData.MsgPtr;

                status = SP007_StartProfile(Cmd);
                SP007_AppData.HkTelemetryPkt.CommandCount++;
                SP007_AppData.HkTelemetryPkt.LastProfileId    = Cmd->ProfileId;
                SP007_AppData.HkTelemetryPkt.LastFlags        = Cmd->Flags;
                SP007_AppData.HkTelemetryPkt.LastDurationMs   = Cmd->DurationMs;
                SP007_AppData.HkTelemetryPkt.LastRateOrYield  = Cmd->RateOrYield;
                SP007_AppData.HkTelemetryPkt.LastLimit        = Cmd->Limit;
                SP007_AppData.HkTelemetryPkt.LastStatus       = status;
                SP007_AppData.HkTelemetryPkt.LastApiStatus    = status;

                if (status == CFE_SUCCESS)
                {
                    SP007_AppData.HkTelemetryPkt.ProfilesStarted++;
                    CFE_EVS_SendEvent(SP007_PROFILE_INF_EID, CFE_EVS_EventType_INFORMATION,
                                      "SP007: profile %u started duration_ms=%lu limit=%lu",
                                      (unsigned int)Cmd->ProfileId, (unsigned long)Cmd->DurationMs,
                                      (unsigned long)Cmd->Limit);
                }
                else
                {
                    SP007_AppData.HkTelemetryPkt.CommandErrorCount++;
                    CFE_EVS_SendEvent(SP007_PROFILE_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "SP007: profile %u start failed RC=0x%08X", (unsigned int)Cmd->ProfileId,
                                      (unsigned int)status);
                }
            }
            break;

        case SP007_STOP_PROFILE_CC:
            if (SP007_VerifyCmdLength(SP007_AppData.MsgPtr, sizeof(SP007_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP007_AppData.HkTelemetryPkt.CommandCount++;
                SP007_StopProfile();
                CFE_EVS_SendEvent(SP007_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP007: stop profile requested");
            }
            break;

        case SP007_CLEANUP_CC:
            if (SP007_VerifyCmdLength(SP007_AppData.MsgPtr, sizeof(SP007_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP007_AppData.HkTelemetryPkt.CommandCount++;
                SP007_StopProfile();
                OS_TaskDelay(5);
                SP007_CleanupResources();
                CFE_EVS_SendEvent(SP007_CLEANUP_INF_EID, CFE_EVS_EventType_INFORMATION, "SP007: cleanup completed");
            }
            break;

        default:
            SP007_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP007_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP007: invalid command code %u",
                              (unsigned int)CommandCode);
            break;
    }
}

static void SP007_ProcessTelemetryRequest(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(SP007_AppData.MsgPtr, &CommandCode);

    if (CommandCode == 0)
    {
        SP007_ReportHousekeeping();
    }
    else
    {
        SP007_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(SP007_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP007: invalid HK request command code %u",
                          (unsigned int)CommandCode);
    }
}

static void SP007_ReportHousekeeping(void)
{
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SP007_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SP007_AppData.HkTelemetryPkt, true);
}

static void SP007_ResetCounters(void)
{
    SP007_AppData.HkTelemetryPkt.CommandErrorCount    = 0;
    SP007_AppData.HkTelemetryPkt.CommandCount         = 0;
    SP007_AppData.HkTelemetryPkt.LastProfileId        = SP007_PROFILE_NONE;
    SP007_AppData.HkTelemetryPkt.LastResourceId       = SP007_RESOURCE_NONE;
    SP007_AppData.HkTelemetryPkt.LastFlags            = 0;
    SP007_AppData.HkTelemetryPkt.LastDurationMs       = 0;
    SP007_AppData.HkTelemetryPkt.LastRateOrYield      = 0;
    SP007_AppData.HkTelemetryPkt.LastLimit            = 0;
    SP007_AppData.HkTelemetryPkt.LastStatus           = 0;
    SP007_AppData.HkTelemetryPkt.ProfilesStarted      = 0;
    SP007_AppData.HkTelemetryPkt.ProfilesCompleted    = 0;
    SP007_AppData.HkTelemetryPkt.StopCount            = 0;
    SP007_AppData.HkTelemetryPkt.CleanupCount         = 0;
    SP007_AppData.HkTelemetryPkt.WorkerTaskCount      = 0;
    SP007_AppData.HkTelemetryPkt.CpuWorkerCount       = 0;
    SP007_AppData.HkTelemetryPkt.SbTransmitCount      = 0;
    SP007_AppData.HkTelemetryPkt.SbTransmitErrorCount = 0;
    SP007_AppData.HkTelemetryPkt.EvsSendCount         = 0;
    SP007_AppData.HkTelemetryPkt.EvsSendErrorCount    = 0;
    SP007_AppData.HkTelemetryPkt.FileBytesWritten     = 0;
    SP007_AppData.HkTelemetryPkt.FileWriteErrorCount  = 0;
    SP007_AppData.HkTelemetryPkt.HeldPipeCount        = 0;
    SP007_AppData.HkTelemetryPkt.HeldQueueCount       = 0;
    SP007_AppData.HkTelemetryPkt.LastApiStatus        = 0;
    SP007_AppData.HkTelemetryPkt.FilePresent          = 0;

    if (!SP007_AppData.ProfileTaskRunning)
    {
        SP007_AppData.HkTelemetryPkt.ActiveProfileId = SP007_PROFILE_NONE;
        SP007_AppData.HkTelemetryPkt.Active          = 0;
        SP007_AppData.HkTelemetryPkt.StopRequested   = 0;
    }
}

static int32 SP007_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength)
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

    SP007_AppData.HkTelemetryPkt.CommandErrorCount++;

    CFE_EVS_SendEvent(SP007_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                      "SP007: invalid length MID=0x%04X CC=%u Len=%lu Expected=%u",
                      (unsigned int)CFE_SB_MsgIdToValue(MsgId), (unsigned int)CommandCode,
                      (unsigned long)ActualLength, (unsigned int)ExpectedLength);

    return CFE_STATUS_WRONG_MSG_LENGTH;
}
