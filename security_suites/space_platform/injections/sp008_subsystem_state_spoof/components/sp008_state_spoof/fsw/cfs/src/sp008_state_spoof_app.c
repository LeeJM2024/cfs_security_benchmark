#include "sp008_state_spoof_app.h"

#include <string.h>

#include "generic_adcs_msg.h"
#include "generic_adcs_msgids.h"
#include "generic_eps_msg.h"
#include "generic_eps_msgids.h"
#include "generic_reaction_wheel_msg.h"
#include "generic_reaction_wheel_msgids.h"
#include "generic_thruster_msg.h"
#include "generic_thruster_msgids.h"
#include "generic_torquer_msg.h"
#include "generic_torquer_msgids.h"
#include "mgr_msg.h"
#include "mgr_msgids.h"
#include "novatel_oem615_msg.h"
#include "novatel_oem615_msgids.h"

SP008_AppData_t SP008_AppData;

static int32 SP008_AppInit(void);
static void  SP008_ProcessPacket(void);
static void  SP008_ProcessGroundCommand(void);
static void  SP008_ProcessTelemetryRequest(void);
static void  SP008_ReportHousekeeping(void);
static void  SP008_ResetCounters(void);
static void  SP008_StartSpoof(uint16 ProfileId);
static void  SP008_StopSpoof(void);
static int32 SP008_TransmitActiveProfile(void);
static int32 SP008_TransmitForgedEpsHk(void);
static int32 SP008_TransmitForgedAdcsGnc(void);
static int32 SP008_TransmitForgedRwHk(void);
static int32 SP008_TransmitForgedThrusterHk(void);
static int32 SP008_TransmitForgedTorquerHk(void);
static int32 SP008_TransmitForgedMgrHk(void);
static int32 SP008_TransmitForgedGpsData(void);
static void  SP008_FillHealthyEpsHk(GENERIC_EPS_Hk_tlm_t *Pkt);
static void  SP008_FillStableAdcsGnc(Generic_ADCS_GNC_Tlm_t *Pkt);
static void  SP008_FillEnabledRwHk(GENERIC_RW_HkTlm_t *Pkt);
static void  SP008_FillEnabledThrusterHk(GENERIC_THRUSTER_Hk_tlm_t *Pkt);
static void  SP008_FillActiveTorquerHk(GENERIC_TORQUER_Hk_tlm_t *Pkt);
static void  SP008_FillMgrScienceHk(MGR_Hk_tlm_t *Pkt);
static void  SP008_FillSpoofedGpsData(NOVATEL_OEM615_Device_tlm_t *Pkt);
static const char *SP008_ProfileName(uint16 ProfileId);

int32 SP008_BenchmarkStart(uint16 profile_id)
{
    SP008_StartSpoof(profile_id);
    return SP008_AppData.SpoofActive ? CFE_SUCCESS : CFE_STATUS_BAD_COMMAND_CODE;
}

void SP008_BenchmarkStop(void)
{
    SP008_StopSpoof();
}
static int32 SP008_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength);

void SP008_AppMain(void)
{
    int32 status = CFE_SUCCESS;

    CFE_ES_PerfLogEntry(SP008_STATE_SPOOF_PERF_ID);

    status = SP008_AppInit();
    if (status != CFE_SUCCESS)
    {
        SP008_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SP008_AppData.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(SP008_STATE_SPOOF_PERF_ID);
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SP008_AppData.MsgPtr, SP008_AppData.CmdPipe,
                                      SP008_DEFAULT_SPOOF_PERIOD_MS);
        CFE_ES_PerfLogEntry(SP008_STATE_SPOOF_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SP008_ProcessPacket();
        }
        else if (status == CFE_SB_TIME_OUT || status == CFE_SB_NO_MESSAGE)
        {
            if (SP008_AppData.SpoofActive)
            {
                SP008_TransmitActiveProfile();
            }
        }
        else
        {
            CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR, "SP008: SB pipe read error = %d",
                              (int)status);
            SP008_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_PerfLogExit(SP008_STATE_SPOOF_PERF_ID);
    CFE_ES_ExitApp(SP008_AppData.RunStatus);
}

static int32 SP008_AppInit(void)
{
    int32 status;

    memset(&SP008_AppData, 0, sizeof(SP008_AppData));
    SP008_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP008_STATE_SPOOF: Error registering for event services: 0x%08X\n",
                             (unsigned int)status);
        return status;
    }

    status = CFE_SB_CreatePipe(&SP008_AppData.CmdPipe, SP008_PIPE_DEPTH, "SP008_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR, "SP008: Error creating SB pipe, RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP008_CMD_MID), SP008_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: Error subscribing to SP008_CMD_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP008_REQ_HK_MID), SP008_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: Error subscribing to SP008_REQ_HK_MID, RC=0x%08X", (unsigned int)status);
        return status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(SP008_AppData.HkTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(SP008_HK_TLM_MID),
                 SP008_HK_TLM_LEN);

    SP008_ResetCounters();

    CFE_EVS_SendEvent(SP008_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP008: subsystem state spoof app initialized");

    return CFE_SUCCESS;
}

static void SP008_ProcessPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(SP008_AppData.MsgPtr, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case SP008_CMD_MID:
            SP008_ProcessGroundCommand();
            break;

        case SP008_REQ_HK_MID:
            SP008_ProcessTelemetryRequest();
            break;

        default:
            SP008_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP008_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP008: received invalid MID 0x%04X",
                              (unsigned int)CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}

static void SP008_ProcessGroundCommand(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(SP008_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        case SP008_NOOP_CC:
            if (SP008_VerifyCmdLength(SP008_AppData.MsgPtr, sizeof(SP008_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP008_AppData.HkTelemetryPkt.CommandCount++;
                CFE_EVS_SendEvent(SP008_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP008: NOOP command received");
            }
            break;

        case SP008_RESET_CC:
            if (SP008_VerifyCmdLength(SP008_AppData.MsgPtr, sizeof(SP008_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP008_ResetCounters();
                CFE_EVS_SendEvent(SP008_CMD_INF_EID, CFE_EVS_EventType_INFORMATION, "SP008: counters reset");
            }
            break;

        case SP008_START_EPS_HEALTHY_SPOOF_CC:
            if (SP008_VerifyCmdLength(SP008_AppData.MsgPtr, sizeof(SP008_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP008_AppData.HkTelemetryPkt.CommandCount++;
                SP008_StartSpoof(SP008_PROFILE_EPS_HEALTHY_WHILE_REAL_LOW_POWER);
            }
            break;

        case SP008_STOP_SPOOF_CC:
            if (SP008_VerifyCmdLength(SP008_AppData.MsgPtr, sizeof(SP008_NoArgsCmd_t)) == CFE_SUCCESS)
            {
                SP008_AppData.HkTelemetryPkt.CommandCount++;
                SP008_StopSpoof();
            }
            break;

        case SP008_START_PROFILE_CC:
            if (SP008_VerifyCmdLength(SP008_AppData.MsgPtr, sizeof(SP008_StartProfileCmd_t)) == CFE_SUCCESS)
            {
                const SP008_StartProfileCmd_t *Cmd = (const SP008_StartProfileCmd_t *)SP008_AppData.MsgPtr;

                SP008_AppData.HkTelemetryPkt.CommandCount++;
                SP008_StartSpoof(Cmd->ProfileId);
            }
            break;

        default:
            SP008_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP008_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP008: invalid command code %u",
                              (unsigned int)CommandCode);
            break;
    }
}

static void SP008_ProcessTelemetryRequest(void)
{
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(SP008_AppData.MsgPtr, &CommandCode);

    if (CommandCode == 0)
    {
        SP008_ReportHousekeeping();
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(SP008_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP008: invalid HK request command code %u",
                          (unsigned int)CommandCode);
    }
}

static void SP008_ReportHousekeeping(void)
{
    SP008_AppData.HkTelemetryPkt.SpoofActive = SP008_AppData.SpoofActive ? 1 : 0;
    SP008_AppData.HkTelemetryPkt.ActiveProfileId = SP008_AppData.ActiveProfileId;
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SP008_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SP008_AppData.HkTelemetryPkt, true);
}

static void SP008_ResetCounters(void)
{
    uint8 i;

    SP008_AppData.HkTelemetryPkt.CommandErrorCount        = 0;
    SP008_AppData.HkTelemetryPkt.CommandCount             = 0;
    SP008_AppData.HkTelemetryPkt.SpoofActive              = SP008_AppData.SpoofActive ? 1 : 0;
    SP008_AppData.HkTelemetryPkt.Reserved                 = 0;
    SP008_AppData.HkTelemetryPkt.ActiveProfileId          = SP008_AppData.ActiveProfileId;
    SP008_AppData.HkTelemetryPkt.LastProfileId            = SP008_PROFILE_NONE;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid           = 0;
    SP008_AppData.HkTelemetryPkt.Reserved16A              = 0;
    SP008_AppData.HkTelemetryPkt.SpoofStartCount          = 0;
    SP008_AppData.HkTelemetryPkt.SpoofStopCount           = 0;
    SP008_AppData.HkTelemetryPkt.ForgedPacketCount        = 0;
    SP008_AppData.HkTelemetryPkt.TransmitErrorCount       = 0;
    SP008_AppData.HkTelemetryPkt.ForgedEpsHkCount         = 0;
    SP008_AppData.HkTelemetryPkt.ForgedAdcsGncCount       = 0;
    SP008_AppData.HkTelemetryPkt.ForgedRwHkCount          = 0;
    SP008_AppData.HkTelemetryPkt.ForgedThrusterHkCount    = 0;
    SP008_AppData.HkTelemetryPkt.ForgedTorquerHkCount     = 0;
    SP008_AppData.HkTelemetryPkt.ForgedMgrHkCount         = 0;
    SP008_AppData.HkTelemetryPkt.ForgedGpsDataCount       = 0;
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus       = 0;
    SP008_AppData.HkTelemetryPkt.LastRawBatteryVoltage    = 28000;
    SP008_AppData.HkTelemetryPkt.LastRawSolarArrayVoltage = 32000;
    SP008_AppData.HkTelemetryPkt.LastSwitch0Status        = SP008_EPS_SWITCH_ON_HEALTHY;
    SP008_AppData.HkTelemetryPkt.LastAdcsMode             = 3;
    SP008_AppData.HkTelemetryPkt.LastAdcsQValid           = 1;
    SP008_AppData.HkTelemetryPkt.Reserved8                = 0;
    for (i = 0; i < 4; i++)
    {
        SP008_AppData.HkTelemetryPkt.LastAdcsQbn[i] = (i == 3) ? 1.0 : 0.0;
    }
    for (i = 0; i < 3; i++)
    {
        SP008_AppData.HkTelemetryPkt.LastAdcsWbn[i] = 0.0;
    }
}

static void SP008_StartSpoof(uint16 ProfileId)
{
    if (ProfileId != SP008_PROFILE_EPS_HEALTHY_WHILE_REAL_LOW_POWER &&
        ProfileId != SP008_PROFILE_ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE &&
        ProfileId != SP008_PROFILE_RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED &&
        ProfileId != SP008_PROFILE_THRUSTER_ENABLED_WHILE_REAL_DISABLED &&
        ProfileId != SP008_PROFILE_TORQUER_ACTIVE_WHILE_REAL_DISABLED &&
        ProfileId != SP008_PROFILE_MGR_SCIENCE_WHILE_REAL_SAFE &&
        ProfileId != SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL)
    {
        SP008_AppData.HkTelemetryPkt.CommandErrorCount++;
        SP008_AppData.HkTelemetryPkt.LastProfileId = ProfileId;
        CFE_EVS_SendEvent(SP008_CMD_ERR_EID, CFE_EVS_EventType_ERROR, "SP008: invalid spoof profile %u",
                          (unsigned int)ProfileId);
        return;
    }

    SP008_AppData.SpoofActive = true;
    SP008_AppData.ActiveProfileId = ProfileId;
    SP008_AppData.HkTelemetryPkt.SpoofActive = 1;
    SP008_AppData.HkTelemetryPkt.ActiveProfileId = ProfileId;
    SP008_AppData.HkTelemetryPkt.LastProfileId = ProfileId;
    SP008_AppData.HkTelemetryPkt.SpoofStartCount++;
    SP008_TransmitActiveProfile();
    CFE_EVS_SendEvent(SP008_SPOOF_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP008: started spoof profile %u (%s)", (unsigned int)ProfileId, SP008_ProfileName(ProfileId));
}

static void SP008_StopSpoof(void)
{
    SP008_AppData.SpoofActive = false;
    SP008_AppData.ActiveProfileId = SP008_PROFILE_NONE;
    SP008_AppData.HkTelemetryPkt.SpoofActive = 0;
    SP008_AppData.HkTelemetryPkt.ActiveProfileId = SP008_PROFILE_NONE;
    SP008_AppData.HkTelemetryPkt.SpoofStopCount++;
    CFE_EVS_SendEvent(SP008_SPOOF_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP008: stopped subsystem state spoof stream");
}

static int32 SP008_TransmitActiveProfile(void)
{
    switch (SP008_AppData.ActiveProfileId)
    {
        case SP008_PROFILE_EPS_HEALTHY_WHILE_REAL_LOW_POWER:
            return SP008_TransmitForgedEpsHk();

        case SP008_PROFILE_ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE:
            return SP008_TransmitForgedAdcsGnc();

        case SP008_PROFILE_RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED:
            return SP008_TransmitForgedRwHk();

        case SP008_PROFILE_THRUSTER_ENABLED_WHILE_REAL_DISABLED:
            return SP008_TransmitForgedThrusterHk();

        case SP008_PROFILE_TORQUER_ACTIVE_WHILE_REAL_DISABLED:
            return SP008_TransmitForgedTorquerHk();

        case SP008_PROFILE_MGR_SCIENCE_WHILE_REAL_SAFE:
            return SP008_TransmitForgedMgrHk();

        case SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL:
            return SP008_TransmitForgedGpsData();

        default:
            SP008_AppData.SpoofActive = false;
            SP008_AppData.HkTelemetryPkt.SpoofActive = 0;
            SP008_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP008_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                              "SP008: no active spoof profile selected");
            return CFE_STATUS_BAD_COMMAND_CODE;
    }
}

static int32 SP008_TransmitForgedEpsHk(void)
{
    GENERIC_EPS_Hk_tlm_t ForgedEpsHk;
    int32                status;

    memset(&ForgedEpsHk, 0, sizeof(ForgedEpsHk));
    CFE_MSG_Init(CFE_MSG_PTR(ForgedEpsHk.TlmHeader), CFE_SB_ValueToMsgId(GENERIC_EPS_HK_TLM_MID),
                 GENERIC_EPS_HK_TLM_LNGTH);
    SP008_FillHealthyEpsHk(&ForgedEpsHk);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&ForgedEpsHk);

    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&ForgedEpsHk, true);
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus = status;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid = GENERIC_EPS_HK_TLM_MID;

    if (status == CFE_SUCCESS)
    {
        SP008_AppData.HkTelemetryPkt.ForgedPacketCount++;
        SP008_AppData.HkTelemetryPkt.ForgedEpsHkCount++;
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.TransmitErrorCount++;
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: forged EPS HK transmit failed, RC=0x%08X", (unsigned int)status);
    }

    return status;
}

static int32 SP008_TransmitForgedAdcsGnc(void)
{
    Generic_ADCS_GNC_Tlm_t ForgedAdcsGnc;
    int32                  status;

    memset(&ForgedAdcsGnc, 0, sizeof(ForgedAdcsGnc));
    CFE_MSG_Init(CFE_MSG_PTR(ForgedAdcsGnc.TlmHeader), CFE_SB_ValueToMsgId(GENERIC_ADCS_GNC_MID),
                 GENERIC_ADCS_GNC_LNGTH);
    SP008_FillStableAdcsGnc(&ForgedAdcsGnc);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&ForgedAdcsGnc);

    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&ForgedAdcsGnc, true);
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus = status;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid = GENERIC_ADCS_GNC_MID;

    if (status == CFE_SUCCESS)
    {
        SP008_AppData.HkTelemetryPkt.ForgedPacketCount++;
        SP008_AppData.HkTelemetryPkt.ForgedAdcsGncCount++;
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.TransmitErrorCount++;
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: forged ADCS GNC transmit failed, RC=0x%08X", (unsigned int)status);
    }

    return status;
}

static int32 SP008_TransmitForgedRwHk(void)
{
    GENERIC_RW_HkTlm_t ForgedRwHk;
    int32              status;

    memset(&ForgedRwHk, 0, sizeof(ForgedRwHk));
    CFE_MSG_Init(CFE_MSG_PTR(ForgedRwHk.TlmHeader), CFE_SB_ValueToMsgId(GENERIC_RW_APP_HK_TLM_MID),
                 sizeof(ForgedRwHk));
    SP008_FillEnabledRwHk(&ForgedRwHk);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&ForgedRwHk);

    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&ForgedRwHk, true);
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus = status;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid = GENERIC_RW_APP_HK_TLM_MID;

    if (status == CFE_SUCCESS)
    {
        SP008_AppData.HkTelemetryPkt.ForgedPacketCount++;
        SP008_AppData.HkTelemetryPkt.ForgedRwHkCount++;
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.TransmitErrorCount++;
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: forged RW HK transmit failed, RC=0x%08X", (unsigned int)status);
    }

    return status;
}

static int32 SP008_TransmitForgedThrusterHk(void)
{
    GENERIC_THRUSTER_Hk_tlm_t ForgedThrusterHk;
    int32                     status;

    memset(&ForgedThrusterHk, 0, sizeof(ForgedThrusterHk));
    CFE_MSG_Init(CFE_MSG_PTR(ForgedThrusterHk.TlmHeader), CFE_SB_ValueToMsgId(GENERIC_THRUSTER_HK_TLM_MID),
                 GENERIC_THRUSTER_HK_TLM_LNGTH);
    SP008_FillEnabledThrusterHk(&ForgedThrusterHk);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&ForgedThrusterHk);

    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&ForgedThrusterHk, true);
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus = status;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid = GENERIC_THRUSTER_HK_TLM_MID;

    if (status == CFE_SUCCESS)
    {
        SP008_AppData.HkTelemetryPkt.ForgedPacketCount++;
        SP008_AppData.HkTelemetryPkt.ForgedThrusterHkCount++;
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.TransmitErrorCount++;
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: forged thruster HK transmit failed, RC=0x%08X", (unsigned int)status);
    }

    return status;
}

static int32 SP008_TransmitForgedTorquerHk(void)
{
    GENERIC_TORQUER_Hk_tlm_t ForgedTorquerHk;
    int32                    status;

    memset(&ForgedTorquerHk, 0, sizeof(ForgedTorquerHk));
    CFE_MSG_Init(CFE_MSG_PTR(ForgedTorquerHk.TlmHeader), CFE_SB_ValueToMsgId(GENERIC_TORQUER_HK_TLM_MID),
                 GENERIC_TORQUER_HK_TLM_LNGTH);
    SP008_FillActiveTorquerHk(&ForgedTorquerHk);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&ForgedTorquerHk);

    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&ForgedTorquerHk, true);
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus = status;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid = GENERIC_TORQUER_HK_TLM_MID;

    if (status == CFE_SUCCESS)
    {
        SP008_AppData.HkTelemetryPkt.ForgedPacketCount++;
        SP008_AppData.HkTelemetryPkt.ForgedTorquerHkCount++;
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.TransmitErrorCount++;
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: forged torquer HK transmit failed, RC=0x%08X", (unsigned int)status);
    }

    return status;
}

static int32 SP008_TransmitForgedMgrHk(void)
{
    MGR_Hk_tlm_t ForgedMgrHk;
    int32        status;

    memset(&ForgedMgrHk, 0, sizeof(ForgedMgrHk));
    CFE_MSG_Init(CFE_MSG_PTR(ForgedMgrHk.TlmHeader), CFE_SB_ValueToMsgId(MGR_HK_TLM_MID), MGR_HK_TLM_LNGTH);
    SP008_FillMgrScienceHk(&ForgedMgrHk);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&ForgedMgrHk);

    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&ForgedMgrHk, true);
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus = status;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid = MGR_HK_TLM_MID;

    if (status == CFE_SUCCESS)
    {
        SP008_AppData.HkTelemetryPkt.ForgedPacketCount++;
        SP008_AppData.HkTelemetryPkt.ForgedMgrHkCount++;
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.TransmitErrorCount++;
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: forged MGR HK transmit failed, RC=0x%08X", (unsigned int)status);
    }

    return status;
}

static int32 SP008_TransmitForgedGpsData(void)
{
    NOVATEL_OEM615_Device_tlm_t ForgedGpsData;
    int32                       status;

    memset(&ForgedGpsData, 0, sizeof(ForgedGpsData));
    CFE_MSG_Init(CFE_MSG_PTR(ForgedGpsData.TlmHeader), CFE_SB_ValueToMsgId(NOVATEL_OEM615_DEVICE_TLM_MID),
                 NOVATEL_OEM615_DEVICE_TLM_LNGTH);
    SP008_FillSpoofedGpsData(&ForgedGpsData);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&ForgedGpsData);

    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&ForgedGpsData, true);
    SP008_AppData.HkTelemetryPkt.LastTransmitStatus = status;
    SP008_AppData.HkTelemetryPkt.LastSpoofedMid = NOVATEL_OEM615_DEVICE_TLM_MID;

    if (status == CFE_SUCCESS)
    {
        SP008_AppData.HkTelemetryPkt.ForgedPacketCount++;
        SP008_AppData.HkTelemetryPkt.ForgedGpsDataCount++;
    }
    else
    {
        SP008_AppData.HkTelemetryPkt.TransmitErrorCount++;
        CFE_EVS_SendEvent(SP008_SPOOF_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP008: forged GPS data transmit failed, RC=0x%08X", (unsigned int)status);
    }

    return status;
}

static void SP008_FillHealthyEpsHk(GENERIC_EPS_Hk_tlm_t *Pkt)
{
    uint8 i;

    Pkt->CommandErrorCount = 0;
    Pkt->CommandCount      = 88;
    Pkt->DeviceErrorCount  = 0;
    Pkt->DeviceCount       = 88;

    Pkt->DeviceHK.BatteryVoltage        = 28000;
    Pkt->DeviceHK.BatteryTemperature    = 8500;
    Pkt->DeviceHK.Bus3p3Voltage         = 3300;
    Pkt->DeviceHK.Bus5p0Voltage         = 5000;
    Pkt->DeviceHK.Bus12Voltage          = 12000;
    Pkt->DeviceHK.EPSTemperature        = 8500;
    Pkt->DeviceHK.SolarArrayVoltage     = 32000;
    Pkt->DeviceHK.SolarArrayTemperature = 8500;

    for (i = 0; i < 8; i++)
    {
        Pkt->DeviceHK.Switch[i].Voltage = (i == 0) ? 5000 : 3300;
        Pkt->DeviceHK.Switch[i].Current = (i == 0) ? 120 : 40;
        Pkt->DeviceHK.Switch[i].Status  = SP008_EPS_SWITCH_ON_HEALTHY;
    }
}

static void SP008_FillStableAdcsGnc(Generic_ADCS_GNC_Tlm_t *Pkt)
{
    uint8 i;

    Pkt->Payload.DT       = 0.1;
    Pkt->Payload.MaxMcmd  = 0.2;
    Pkt->Payload.Mode     = 3;
    Pkt->Payload.HmgmtOn  = 0;
    Pkt->Payload.SunValid = 1;
    Pkt->Payload.qValid   = 1;

    Pkt->Payload.Hmgmt.Kb      = 100.0;
    Pkt->Payload.Hmgmt.b_range = 0.00005;
    Pkt->Payload.Hmgmt.loFrac  = 0.2;
    Pkt->Payload.Hmgmt.hiFrac  = 0.8;

    for (i = 0; i < 3; i++)
    {
        Pkt->Payload.Hmgmt.mm_active[i] = 0;
        Pkt->Payload.Hmgmt.Mcmd[i]      = 0.0;
        Pkt->Payload.bvb[i]             = 0.00002;
        Pkt->Payload.svb[i]             = (i == 2) ? 1.0 : 0.0;
        Pkt->Payload.wbn[i]             = 0.0;
        Pkt->Payload.HwhlMaxB[i]        = 0.02;
        Pkt->Payload.HwhlB[i]           = 0.0;
        Pkt->Payload.Mcmd[i]            = 0.0;
        Pkt->Payload.Tcmd[i]            = 0.0;
        SP008_AppData.HkTelemetryPkt.LastAdcsWbn[i] = Pkt->Payload.wbn[i];
    }

    for (i = 0; i < 4; i++)
    {
        Pkt->Payload.qbn[i]  = (i == 3) ? 1.0 : 0.0;
        Pkt->Payload.qErr[i] = (i == 3) ? 1.0 : 0.0;
        SP008_AppData.HkTelemetryPkt.LastAdcsQbn[i] = Pkt->Payload.qbn[i];
    }

    SP008_AppData.HkTelemetryPkt.LastAdcsMode   = Pkt->Payload.Mode;
    SP008_AppData.HkTelemetryPkt.LastAdcsQValid = Pkt->Payload.qValid;
}

static void SP008_FillEnabledRwHk(GENERIC_RW_HkTlm_t *Pkt)
{
    uint8 i;

    Pkt->Payload.CommandErrorCounter = 0;
    Pkt->Payload.CommandCounter      = 42;
    Pkt->Payload.DeviceErrorCount_RW0 = 0;
    Pkt->Payload.DeviceErrorCount_RW1 = 0;
    Pkt->Payload.DeviceErrorCount_RW2 = 0;
    Pkt->Payload.DeviceCount_RW0      = 42;
    Pkt->Payload.DeviceCount_RW1      = 42;
    Pkt->Payload.DeviceCount_RW2      = 42;
    Pkt->Payload.DeviceEnabled_RW0    = 1;
    Pkt->Payload.DeviceEnabled_RW1    = 1;
    Pkt->Payload.DeviceEnabled_RW2    = 1;

    for (i = 0; i < 3; i++)
    {
        Pkt->Payload.data.momentum[i] = 0.001;
    }
}

static void SP008_FillEnabledThrusterHk(GENERIC_THRUSTER_Hk_tlm_t *Pkt)
{
    Pkt->CommandErrorCount = 0;
    Pkt->CommandCount      = 17;
    Pkt->DeviceErrorCount  = 0;
    Pkt->DeviceCount       = 17;
    Pkt->DeviceEnabled     = 1;
}

static void SP008_FillActiveTorquerHk(GENERIC_TORQUER_Hk_tlm_t *Pkt)
{
    uint8 i;

    Pkt->CommandErrorCount = 0;
    Pkt->CommandCount      = 23;
    Pkt->DeviceErrorCount  = 0;
    Pkt->DeviceCount       = 23;
    Pkt->DeviceEnabled     = 1;
    Pkt->TorquerPeriod     = 1000;

    for (i = 0; i < 3; i++)
    {
        Pkt->TrqInfo[i].Direction = 1;
        Pkt->TrqInfo[i].PercentOn = 25;
    }
}

static void SP008_FillMgrScienceHk(MGR_Hk_tlm_t *Pkt)
{
    Pkt->CommandErrorCount = 0;
    Pkt->CommandCount      = 31;
    Pkt->SpacecraftMode    = 3;
    Pkt->BootCounter       = 1;
    Pkt->AnomRebootCtr     = 0;
    Pkt->TimeTics          = 0;
    Pkt->ScienceStatus     = 2;
    Pkt->SciPassCount      = 1;
    Pkt->AkConfig          = 1;
    Pkt->ConusConfig       = 1;
    Pkt->HiConfig          = 1;
}

static void SP008_FillSpoofedGpsData(NOVATEL_OEM615_Device_tlm_t *Pkt)
{
    Pkt->Novatel_oem615.Weeks           = 2400;
    Pkt->Novatel_oem615.SecondsIntoWeek = 345600;
    Pkt->Novatel_oem615.Fractions       = 0.125;
    /* Deliberately distinct from the GPSFILE baseline used by NOS3. */
    Pkt->Novatel_oem615.ECEFX           = 4160000.0;
    Pkt->Novatel_oem615.ECEFY           = -9000.0;
    Pkt->Novatel_oem615.ECEFZ           = 5360000.0;
    Pkt->Novatel_oem615.VelX            = -7000.0;
    Pkt->Novatel_oem615.VelY            = 1000.0;
    Pkt->Novatel_oem615.VelZ            = 0.0;
    Pkt->Novatel_oem615.lat             = 51.5074f;
    Pkt->Novatel_oem615.lon             = -0.1278f;
    Pkt->Novatel_oem615.alt             = 500000.0f;
}

static const char *SP008_ProfileName(uint16 ProfileId)
{
    switch (ProfileId)
    {
        case SP008_PROFILE_EPS_HEALTHY_WHILE_REAL_LOW_POWER:
            return "EPS_HEALTHY_WHILE_REAL_LOW_POWER";

        case SP008_PROFILE_ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE:
            return "ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE";

        case SP008_PROFILE_RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED:
            return "RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED";

        case SP008_PROFILE_THRUSTER_ENABLED_WHILE_REAL_DISABLED:
            return "THRUSTER_ENABLED_WHILE_REAL_DISABLED";

        case SP008_PROFILE_TORQUER_ACTIVE_WHILE_REAL_DISABLED:
            return "TORQUER_ACTIVE_WHILE_REAL_DISABLED";

        case SP008_PROFILE_MGR_SCIENCE_WHILE_REAL_SAFE:
            return "MGR_SCIENCE_WHILE_REAL_SAFE";

        case SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL:
            return "GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL";

        default:
            return "UNKNOWN";
    }
}

static int32 SP008_VerifyCmdLength(CFE_MSG_Message_t *Msg, uint16 ExpectedLength)
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

    SP008_AppData.HkTelemetryPkt.CommandErrorCount++;
    CFE_EVS_SendEvent(SP008_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                      "SP008: invalid length MID=0x%04X CC=%u Len=%lu Expected=%u",
                      (unsigned int)CFE_SB_MsgIdToValue(MsgId), (unsigned int)CommandCode,
                      (unsigned long)ActualLength, (unsigned int)ExpectedLength);

    return CFE_STATUS_WRONG_MSG_LENGTH;
}
