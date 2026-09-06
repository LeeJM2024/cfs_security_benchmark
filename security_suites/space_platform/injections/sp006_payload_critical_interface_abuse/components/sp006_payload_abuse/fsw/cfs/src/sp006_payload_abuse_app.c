#include "sp006_payload_abuse_app.h"

#include <string.h>

SP006_AppData_t SP006_AppData;

static int32 SP006_AppInit(void);
static void  SP006_ProcessPacket(void);
static void  SP006_ProcessGroundCommand(void);
static void  SP006_ProcessTelemetryRequest(void);
static void  SP006_ReportHousekeeping(void);
static void  SP006_ResetCounters(void);
static int32 SP006_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength);

void SP006_AppMain(void)
{
    int32 status = CFE_SUCCESS;

    CFE_ES_PerfLogEntry(SP006_PAYLOAD_ABUSE_PERF_ID);

    status = SP006_AppInit();
    if (status != CFE_SUCCESS)
    {
        SP006_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SP006_AppData.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(SP006_PAYLOAD_ABUSE_PERF_ID);

        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SP006_AppData.MsgPtr, SP006_AppData.CmdPipe,
                                      CFE_SB_PEND_FOREVER);

        CFE_ES_PerfLogEntry(SP006_PAYLOAD_ABUSE_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SP006_ProcessPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SP006_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP006: SB pipe read error = 0x%08X",
                              (unsigned int)status);
            SP006_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_PerfLogExit(SP006_PAYLOAD_ABUSE_PERF_ID);
    CFE_ES_ExitApp(SP006_AppData.RunStatus);
}

static int32 SP006_AppInit(void)
{
    int32 status;

    memset(&SP006_AppData, 0, sizeof(SP006_AppData));
    SP006_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP006: Error registering for event services: 0x%08X\n", (unsigned int)status);
        return status;
    }

    status = CFE_SB_CreatePipe(&SP006_AppData.CmdPipe, SP006_PIPE_DEPTH, "SP006_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP006_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP006: Error creating SB pipe, RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP006_CMD_MID), SP006_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP006_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP006: Error subscribing to SP006_CMD_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP006_REQ_HK_MID), SP006_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP006_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP006: Error subscribing to SP006_REQ_HK_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(SP006_AppData.HkTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(SP006_HK_TLM_MID),
                 SP006_HK_TLM_LEN);

    SP006_ResetCounters();

    CFE_EVS_SendEvent(SP006_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP006: payload critical interface abuse app initialized");

    return CFE_SUCCESS;
}

static void SP006_ProcessPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(SP006_AppData.MsgPtr, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case SP006_CMD_MID:
            SP006_ProcessGroundCommand();
            break;

        case SP006_REQ_HK_MID:
            SP006_ProcessTelemetryRequest();
            break;

        default:
            SP006_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP006_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP006: received invalid MID 0x%04X",
                              (unsigned int)CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}

static void SP006_ProcessGroundCommand(void)
{
    CFE_MSG_FcnCode_t    CommandCode = 0;
    int32                status      = CFE_SUCCESS;
    SP006_ProfileResult_t result;

    CFE_MSG_GetFcnCode(SP006_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        case SP006_NOOP_CC:
            if (SP006_VerifyCmdLength(SP006_AppData.MsgPtr, sizeof(SP006_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP006_AppData.HkTelemetryPkt.CommandCount++;
                CFE_EVS_SendEvent(SP006_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP006: NOOP command received");
            }
            break;

        case SP006_RESET_CC:
            if (SP006_VerifyCmdLength(SP006_AppData.MsgPtr, sizeof(SP006_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP006_ResetCounters();
                CFE_EVS_SendEvent(SP006_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP006: counters reset");
            }
            break;

        case SP006_RUN_PROFILE_CC:
            if (SP006_VerifyCmdLength(SP006_AppData.MsgPtr, sizeof(SP006_RunProfileCmd_t)) == CFE_SUCCESS)
            {
                const SP006_RunProfileCmd_t *Cmd = (const SP006_RunProfileCmd_t *)SP006_AppData.MsgPtr;

                memset(&result, 0, sizeof(result));
                status = SP006_RunProfile(Cmd, &result);

                SP006_AppData.HkTelemetryPkt.CommandCount++;
                SP006_AppData.HkTelemetryPkt.LastProfileId     = Cmd->ProfileId;
                SP006_AppData.HkTelemetryPkt.LastStatus        = status;
                SP006_AppData.HkTelemetryPkt.LastTargetId      = result.TargetId;
                SP006_AppData.HkTelemetryPkt.LastTargetMsgId   = result.MsgId;
                SP006_AppData.HkTelemetryPkt.LastTargetFcnCode = result.FcnCode;
                SP006_AppData.HkTelemetryPkt.LastRepeatCount   = result.SentCount;
                SP006_AppData.HkTelemetryPkt.LastArg1          = Cmd->Arg1;
                SP006_AppData.HkTelemetryPkt.LastArg2          = Cmd->Arg2;

                if (status == CFE_SUCCESS)
                {
                    SP006_AppData.HkTelemetryPkt.ProfilesExecuted++;
                    SP006_AppData.HkTelemetryPkt.TargetCommandCount += result.SentCount;
                    if (result.SentCount > 1)
                    {
                        SP006_AppData.HkTelemetryPkt.MultiCommandCount += result.SentCount;
                    }
                    CFE_EVS_SendEvent(SP006_PROFILE_INF_EID, CFE_EVS_EventType_INFORMATION,
                                      "SP006: profile %u sent %u command(s) to MID=0x%04X FC=%u",
                                      (unsigned int)Cmd->ProfileId, (unsigned int)result.SentCount,
                                      (unsigned int)result.MsgId, (unsigned int)result.FcnCode);
                }
                else
                {
                    SP006_AppData.HkTelemetryPkt.CommandErrorCount++;
                    SP006_AppData.HkTelemetryPkt.TargetCommandErrorCount++;
                    CFE_EVS_SendEvent(SP006_PROFILE_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "SP006: profile %u failed RC=0x%08X", (unsigned int)Cmd->ProfileId,
                                      (unsigned int)status);
                }
            }
            break;

        default:
            SP006_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP006_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP006: invalid command code %u",
                              (unsigned int)CommandCode);
            break;
    }
}

static void SP006_ProcessTelemetryRequest(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(SP006_AppData.MsgPtr, &CommandCode);

    if (CommandCode == 0)
    {
        SP006_ReportHousekeeping();
    }
    else
    {
        SP006_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(SP006_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP006: invalid HK request command code %u",
                          (unsigned int)CommandCode);
    }
}

static void SP006_ReportHousekeeping(void)
{
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SP006_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SP006_AppData.HkTelemetryPkt, true);
}

static void SP006_ResetCounters(void)
{
    SP006_AppData.HkTelemetryPkt.CommandErrorCount       = 0;
    SP006_AppData.HkTelemetryPkt.CommandCount            = 0;
    SP006_AppData.HkTelemetryPkt.LastProfileId           = 0;
    SP006_AppData.HkTelemetryPkt.LastTargetId            = SP006_TARGET_NONE;
    SP006_AppData.HkTelemetryPkt.LastTargetFcnCode       = 0;
    SP006_AppData.HkTelemetryPkt.LastRepeatCount         = 0;
    SP006_AppData.HkTelemetryPkt.LastStatus              = 0;
    SP006_AppData.HkTelemetryPkt.LastArg1                = 0;
    SP006_AppData.HkTelemetryPkt.LastArg2                = 0;
    SP006_AppData.HkTelemetryPkt.ProfilesExecuted        = 0;
    SP006_AppData.HkTelemetryPkt.TargetCommandCount      = 0;
    SP006_AppData.HkTelemetryPkt.TargetCommandErrorCount = 0;
    SP006_AppData.HkTelemetryPkt.MultiCommandCount       = 0;
    SP006_AppData.HkTelemetryPkt.LastTargetMsgId         = 0;
}

static int32 SP006_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength)
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

    SP006_AppData.HkTelemetryPkt.CommandErrorCount++;

    CFE_EVS_SendEvent(SP006_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                      "SP006: invalid length MID=0x%04X CC=%u Len=%lu Expected=%u",
                      (unsigned int)CFE_SB_MsgIdToValue(MsgId), (unsigned int)CommandCode,
                      (unsigned long)ActualLength, (unsigned int)ExpectedLength);

    return CFE_STATUS_WRONG_MSG_LENGTH;
}
