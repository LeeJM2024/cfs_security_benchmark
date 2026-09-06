#include "sp004_table_tamper_app.h"

#include <string.h>

SP004_AppData_t SP004_AppData;

static int32 SP004_AppInit(void);
static void  SP004_ProcessPacket(void);
static void  SP004_ProcessGroundCommand(void);
static void  SP004_ProcessTelemetryRequest(void);
static void  SP004_ReportHousekeeping(void);
static void  SP004_ResetCounters(void);
static int32 SP004_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength);

void SP004_AppMain(void)
{
    int32 status = CFE_SUCCESS;

    CFE_ES_PerfLogEntry(SP004_TABLE_TAMPER_PERF_ID);

    status = SP004_AppInit();
    if (status != CFE_SUCCESS)
    {
        SP004_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SP004_AppData.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(SP004_TABLE_TAMPER_PERF_ID);

        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SP004_AppData.MsgPtr, SP004_AppData.CmdPipe,
                                      CFE_SB_PEND_FOREVER);

        CFE_ES_PerfLogEntry(SP004_TABLE_TAMPER_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SP004_ProcessPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SP004_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP004: SB pipe read error = 0x%08X",
                              (unsigned int)status);
            SP004_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_PerfLogExit(SP004_TABLE_TAMPER_PERF_ID);
    CFE_ES_ExitApp(SP004_AppData.RunStatus);
}

static int32 SP004_AppInit(void)
{
    int32 status;

    memset(&SP004_AppData, 0, sizeof(SP004_AppData));
    SP004_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP004: Error registering for event services: 0x%08X\n", (unsigned int)status);
        return status;
    }

    status = CFE_SB_CreatePipe(&SP004_AppData.CmdPipe, SP004_PIPE_DEPTH, "SP004_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP004_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR, "SP004: Error creating SB pipe, RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP004_CMD_MID), SP004_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP004_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP004: Error subscribing to SP004_CMD_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP004_REQ_HK_MID), SP004_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP004_RUNTIME_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP004: Error subscribing to SP004_REQ_HK_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(SP004_AppData.HkTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(SP004_HK_TLM_MID),
                 SP004_HK_TLM_LEN);

    SP004_ResetCounters();

    CFE_EVS_SendEvent(SP004_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP004: table/config tamper app initialized");

    return CFE_SUCCESS;
}

static void SP004_ProcessPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(SP004_AppData.MsgPtr, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case SP004_CMD_MID:
            SP004_ProcessGroundCommand();
            break;

        case SP004_REQ_HK_MID:
            SP004_ProcessTelemetryRequest();
            break;

        default:
            SP004_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP004_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP004: received invalid MID 0x%04X",
                              (unsigned int)CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}

static void SP004_ProcessGroundCommand(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;
    int32             status      = CFE_SUCCESS;

    CFE_MSG_GetFcnCode(SP004_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        case SP004_NOOP_CC:
            if (SP004_VerifyCmdLength(SP004_AppData.MsgPtr, sizeof(SP004_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP004_AppData.HkTelemetryPkt.CommandCount++;
                CFE_EVS_SendEvent(SP004_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP004: NOOP command received");
            }
            break;

        case SP004_RESET_CC:
            if (SP004_VerifyCmdLength(SP004_AppData.MsgPtr, sizeof(SP004_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP004_ResetCounters();
                CFE_EVS_SendEvent(SP004_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP004: counters reset");
            }
            break;

        case SP004_RUN_PROFILE_CC:
            if (SP004_VerifyCmdLength(SP004_AppData.MsgPtr, sizeof(SP004_RunProfileCmd_t)) == CFE_SUCCESS)
            {
                const SP004_RunProfileCmd_t *Cmd = (const SP004_RunProfileCmd_t *)SP004_AppData.MsgPtr;

                SP004_AppData.HkTelemetryPkt.LastProfileId = Cmd->ProfileId;
                SP004_AppData.HkTelemetryPkt.LastTargetId  = Cmd->TargetId;
                SP004_AppData.HkTelemetryPkt.LastStatus    = CFE_SUCCESS;
                SP004_AppData.HkTelemetryPkt.LastTblStatus = CFE_SUCCESS;

                status = SP004_RunProfile(Cmd);

                SP004_AppData.HkTelemetryPkt.CommandCount++;
                SP004_AppData.HkTelemetryPkt.LastStatus = status;

                if (status == CFE_SUCCESS)
                {
                    SP004_AppData.HkTelemetryPkt.ProfilesExecuted++;
                    CFE_EVS_SendEvent(SP004_TBL_INF_EID, CFE_EVS_EventType_INFORMATION,
                                      "SP004: profile %u executed target=%u",
                                      (unsigned int)Cmd->ProfileId, (unsigned int)Cmd->TargetId);
                }
                else
                {
                    SP004_AppData.HkTelemetryPkt.CommandErrorCount++;
                    CFE_EVS_SendEvent(SP004_TBL_ERR_EID, CFE_EVS_EventType_ERROR,
                                      "SP004: profile %u failed target=%u RC=0x%08X",
                                      (unsigned int)Cmd->ProfileId, (unsigned int)Cmd->TargetId,
                                      (unsigned int)status);
                }
            }
            break;

        default:
            SP004_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP004_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP004: invalid command code %u",
                              (unsigned int)CommandCode);
            break;
    }
}

static void SP004_ProcessTelemetryRequest(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(SP004_AppData.MsgPtr, &CommandCode);

    if (CommandCode == 0)
    {
        SP004_ReportHousekeeping();
    }
    else
    {
        SP004_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(SP004_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP004: invalid HK request command code %u",
                          (unsigned int)CommandCode);
    }
}

static void SP004_ReportHousekeeping(void)
{
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SP004_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SP004_AppData.HkTelemetryPkt, true);
}

static void SP004_ResetCounters(void)
{
    SP004_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SP004_AppData.HkTelemetryPkt.CommandCount      = 0;
    SP004_AppData.HkTelemetryPkt.LastProfileId     = 0;
    SP004_AppData.HkTelemetryPkt.LastTargetId      = 0;
    SP004_AppData.HkTelemetryPkt.LastActionMask    = 0;
    SP004_AppData.HkTelemetryPkt.LastStatus        = 0;
    SP004_AppData.HkTelemetryPkt.LastTblStatus     = 0;
    SP004_AppData.HkTelemetryPkt.ProfilesExecuted  = 0;
    SP004_AppData.HkTelemetryPkt.TblLoadCount      = 0;
    SP004_AppData.HkTelemetryPkt.TblValidateCount  = 0;
    SP004_AppData.HkTelemetryPkt.TblActivateCount  = 0;
    SP004_AppData.HkTelemetryPkt.TblDumpCount      = 0;
    SP004_AppData.HkTelemetryPkt.TblRegistryCount  = 0;
    SP004_AppData.HkTelemetryPkt.TblAbortCount     = 0;
    SP004_AppData.HkTelemetryPkt.RestoreCount      = 0;
    SP004_AppData.HkTelemetryPkt.TxErrorCount      = 0;
    memset(SP004_AppData.HkTelemetryPkt.LastTableName, 0, sizeof(SP004_AppData.HkTelemetryPkt.LastTableName));
    memset(SP004_AppData.HkTelemetryPkt.LastLoadFilename, 0, sizeof(SP004_AppData.HkTelemetryPkt.LastLoadFilename));
    memset(SP004_AppData.HkTelemetryPkt.LastDumpFilename, 0, sizeof(SP004_AppData.HkTelemetryPkt.LastDumpFilename));
}

static int32 SP004_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength)
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

    SP004_AppData.HkTelemetryPkt.CommandErrorCount++;

    CFE_EVS_SendEvent(SP004_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                      "SP004: invalid length MID=0x%04X CC=%u Len=%lu Expected=%u",
                      (unsigned int)CFE_SB_MsgIdToValue(MsgId), (unsigned int)CommandCode,
                      (unsigned long)ActualLength, (unsigned int)ExpectedLength);

    return CFE_STATUS_WRONG_MSG_LENGTH;
}
