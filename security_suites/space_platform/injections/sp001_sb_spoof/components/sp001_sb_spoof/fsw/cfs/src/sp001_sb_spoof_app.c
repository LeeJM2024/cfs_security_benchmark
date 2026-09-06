#include "sp001_sb_spoof_app.h"

#include <string.h>

SP001_AppData_t SP001_AppData;

static int32 SP001_AppInit(void);
static void  SP001_ProcessPacket(void);
static void  SP001_ProcessGroundCommand(void);
static void  SP001_ProcessTelemetryRequest(void);
static void  SP001_ReportHousekeeping(void);
static void  SP001_ResetCounters(void);
static int32 SP001_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength);

void SP001_AppMain(void)
{
    int32 status = CFE_SUCCESS;

    CFE_ES_PerfLogEntry(SP001_SB_SPOOF_PERF_ID);

    status = SP001_AppInit();
    if (status != CFE_SUCCESS)
    {
        SP001_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SP001_AppData.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(SP001_SB_SPOOF_PERF_ID);

        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SP001_AppData.MsgPtr, SP001_AppData.CmdPipe,
                                      CFE_SB_PEND_FOREVER);

        CFE_ES_PerfLogEntry(SP001_SB_SPOOF_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SP001_ProcessPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SP001_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR, "SP001: SB pipe read error = %d",
                              (int)status);
            SP001_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_PerfLogExit(SP001_SB_SPOOF_PERF_ID);
    CFE_ES_ExitApp(SP001_AppData.RunStatus);
}

static int32 SP001_AppInit(void)
{
    int32 status;

    memset(&SP001_AppData, 0, sizeof(SP001_AppData));
    SP001_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP001_SB_SPOOF: Error registering for event services: 0x%08X\n", (unsigned int)status);
        return status;
    }

    status = CFE_SB_CreatePipe(&SP001_AppData.CmdPipe, SP001_PIPE_DEPTH, "SP001_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP001_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR, "SP001: Error creating SB pipe, RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP001_CMD_MID), SP001_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP001_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP001: Error subscribing to SP001_CMD_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP001_REQ_HK_MID), SP001_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP001_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP001: Error subscribing to SP001_REQ_HK_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(SP001_AppData.HkTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(SP001_HK_TLM_MID),
                 SP001_HK_TLM_LEN);

    SP001_ResetCounters();

    CFE_EVS_SendEvent(SP001_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP001: command-driven SB spoof app initialized");

    return CFE_SUCCESS;
}

static void SP001_ProcessPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(SP001_AppData.MsgPtr, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case SP001_CMD_MID:
            SP001_ProcessGroundCommand();
            break;

        case SP001_REQ_HK_MID:
            SP001_ProcessTelemetryRequest();
            break;

        default:
            SP001_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP001_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR, "SP001: received invalid MID 0x%04X",
                              (unsigned int)CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}

static void SP001_ProcessGroundCommand(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;
    int32             status      = CFE_SUCCESS;

    CFE_MSG_GetFcnCode(SP001_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        case SP001_NOOP_CC:
            if (SP001_VerifyCmdLength(SP001_AppData.MsgPtr, sizeof(SP001_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP001_AppData.HkTelemetryPkt.CommandCount++;
                CFE_EVS_SendEvent(SP001_SPOOF_INF_EID, CFE_EVS_EventType_INFORMATION, "SP001: NOOP command received");
            }
            break;

        case SP001_RESET_CC:
            if (SP001_VerifyCmdLength(SP001_AppData.MsgPtr, sizeof(SP001_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP001_ResetCounters();
                CFE_EVS_SendEvent(SP001_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP001: counters reset");
            }
            break;

        case SP001_RUN_PROFILE_CC:
            if (SP001_VerifyCmdLength(SP001_AppData.MsgPtr, sizeof(SP001_RunProfileCmd_t)) == CFE_SUCCESS)
            {
                const SP001_RunProfileCmd_t *Cmd = (const SP001_RunProfileCmd_t *)SP001_AppData.MsgPtr;

                status = SP001_RunProfile(Cmd);

                SP001_AppData.HkTelemetryPkt.CommandCount++;
                SP001_AppData.HkTelemetryPkt.LastProfileId = Cmd->ProfileId;
                SP001_AppData.HkTelemetryPkt.LastStatus    = status;

                if (status == CFE_SUCCESS)
                {
                    SP001_AppData.HkTelemetryPkt.ProfilesExecuted++;
                    CFE_EVS_SendEvent(SP001_SPOOF_INF_EID, CFE_EVS_EventType_INFORMATION,
                                      "SP001: profile %u spoof transmitted", (unsigned int)Cmd->ProfileId);
                }
                else
                {
                    SP001_AppData.HkTelemetryPkt.CommandErrorCount++;
                    CFE_EVS_SendEvent(SP001_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "SP001: profile %u spoof failed, RC=0x%08X", (unsigned int)Cmd->ProfileId,
                                      (unsigned int)status);
                }
            }
            break;

        default:
            SP001_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP001_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP001: invalid command code %u",
                              (unsigned int)CommandCode);
            break;
    }
}

static void SP001_ProcessTelemetryRequest(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(SP001_AppData.MsgPtr, &CommandCode);

    if (CommandCode == 0)
    {
        SP001_ReportHousekeeping();
    }
    else
    {
        SP001_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(SP001_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP001: invalid HK request command code %u",
                          (unsigned int)CommandCode);
    }
}

static void SP001_ReportHousekeeping(void)
{
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SP001_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SP001_AppData.HkTelemetryPkt, true);
}

static void SP001_ResetCounters(void)
{
    SP001_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SP001_AppData.HkTelemetryPkt.CommandCount      = 0;
    SP001_AppData.HkTelemetryPkt.LastProfileId     = 0;
    SP001_AppData.HkTelemetryPkt.LastStatus        = 0;
    SP001_AppData.HkTelemetryPkt.ProfilesExecuted  = 0;
}

static int32 SP001_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength)
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

    SP001_AppData.HkTelemetryPkt.CommandErrorCount++;

    CFE_EVS_SendEvent(SP001_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                      "SP001: invalid length MID=0x%04X CC=%u Len=%lu Expected=%u",
                      (unsigned int)CFE_SB_MsgIdToValue(MsgId), (unsigned int)CommandCode,
                      (unsigned long)ActualLength, (unsigned int)ExpectedLength);

    return CFE_STATUS_WRONG_MSG_LENGTH;
}
