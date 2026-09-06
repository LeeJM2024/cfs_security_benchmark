#include "sp006_payload_abuse_profiles.h"

#include <string.h>

#include "cam_msgids.h"
#include "generic_reaction_wheel_msgids.h"
#include "generic_thruster_msgids.h"

#define SP006_CAM_EXP3_CC 12
#define SP006_CAM_STOP_CC 2
#define SP006_CAM_PAUSE_CC 3
#define SP006_CAM_TIMEOUT_CC 5
#define SP006_CAM_LOW_VOLTAGE_CC 6
#define SP006_CAM_HWLIB_CAPTURE_CC 29
#define SP006_CAM_HWLIB_READ_CC 31

#define SP006_GENERIC_RW_APP_SET_TORQUE_CC 3
#define SP006_GENERIC_THRUSTER_PERCENTAGE_CC 4

#define SP006_DEFAULT_CAM_INTERRUPT_CC SP006_CAM_LOW_VOLTAGE_CC
#define SP006_DEFAULT_CAM_INTERRUPT_DELAY_MS 100
#define SP006_DEFAULT_RW_WHEEL 0
#define SP006_DEFAULT_RW_TORQUE_UNITS 2500
#define SP006_DEFAULT_THRUSTER_NUMBER 0
#define SP006_DEFAULT_THRUSTER_PERCENTAGE 75

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint8                   wheel_number;
    int16                   data;
} __attribute__((packed)) SP006_RwCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint8                   ThrusterNumber;
    uint8                   Percentage;
} SP006_ThrusterPercentageCmd_t;

static uint16 SP006_NormalizeDelay(uint16 DelayMs, uint16 DefaultDelayMs);
static int32  SP006_SendNoArgsCmd(CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode);
static int32  SP006_RunCamHwlibOutOfOrder(uint16 DelayMs, uint16 *SentCount, CFE_MSG_FcnCode_t *LastFcnCode);
static int32  SP006_RunCamCollectionInterrupt(int32 InterruptArg, uint16 DelayMs, uint16 *SentCount,
                                              CFE_MSG_FcnCode_t *LastFcnCode);
static int32  SP006_SendRwSetTorque(int32 WheelArg, int32 TorqueArg);
static int32  SP006_SendThrusterPercentage(int32 ThrusterArg, int32 PercentageArg);
static void   SP006_FillResult(SP006_ProfileResult_t *Result, CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode,
                               uint16 TargetId, uint16 SentCount, int32 Status);

int32 SP006_RunProfile(const SP006_RunProfileCmd_t *Cmd, SP006_ProfileResult_t *Result)
{
    int32             status;
    uint16            sent_count = 0;
    CFE_MSG_FcnCode_t last_fcn_code = 0;

    if (Cmd == NULL || Result == NULL)
    {
        return CFE_STATUS_BAD_COMMAND_CODE;
    }

    memset(Result, 0, sizeof(*Result));

    switch (Cmd->ProfileId)
    {
        case SP006_PROFILE_CAM_HWLIB_OUT_OF_ORDER: // 绕过正常实验流程，直接调用底层的 HWLIB 命令（即capture/read这类命令）
            status = SP006_RunCamHwlibOutOfOrder(Cmd->DelayMs, &sent_count, &last_fcn_code);
            SP006_FillResult(Result, CAM_CMD_MID, last_fcn_code, SP006_TARGET_CAM, sent_count, status);
            return status;

        case SP006_PROFILE_CAM_COLLECTION_INTERRUPT:
            status = SP006_RunCamCollectionInterrupt(Cmd->Arg1, Cmd->DelayMs, &sent_count, &last_fcn_code);
            SP006_FillResult(Result, CAM_CMD_MID, last_fcn_code, SP006_TARGET_CAM, sent_count, status);
            return status;

        case SP006_PROFILE_RW_DISABLED_SET_TORQUE: // 禁用状态下尝试输出命令
            status = SP006_SendRwSetTorque(Cmd->Arg1, Cmd->Arg2);
            SP006_FillResult(Result, GENERIC_RW_APP_CMD_MID, SP006_GENERIC_RW_APP_SET_TORQUE_CC, SP006_TARGET_RW, 1,
                             status);
            return status;

        case SP006_PROFILE_THRUSTER_DISABLED_PERCENTAGE: // 禁用状态下尝试输出命令
            status = SP006_SendThrusterPercentage(Cmd->Arg1, Cmd->Arg2);
            SP006_FillResult(Result, GENERIC_THRUSTER_CMD_MID, SP006_GENERIC_THRUSTER_PERCENTAGE_CC,
                             SP006_TARGET_THRUSTER, 1, status);
            return status;

        default:
            SP006_FillResult(Result, 0, 0, SP006_TARGET_NONE, 0, CFE_STATUS_BAD_COMMAND_CODE);
            return CFE_STATUS_BAD_COMMAND_CODE;
    }
}

static uint16 SP006_NormalizeDelay(uint16 DelayMs, uint16 DefaultDelayMs)
{
    if (DelayMs == 0)
    {
        DelayMs = DefaultDelayMs;
    }
    if (DelayMs > SP006_MAX_DELAY_MS)
    {
        DelayMs = SP006_MAX_DELAY_MS;
    }
    return DelayMs;
}

static int32 SP006_SendNoArgsCmd(CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode)
{
    SP006_NoArgsCmd_t AbuseCmd;

    memset(&AbuseCmd, 0, sizeof(AbuseCmd));
    CFE_MSG_Init(CFE_MSG_PTR(AbuseCmd.CmdHeader), CFE_SB_ValueToMsgId(MsgId), sizeof(AbuseCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&AbuseCmd, FcnCode);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&AbuseCmd);

    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&AbuseCmd, true);
}

static int32 SP006_RunCamHwlibOutOfOrder(uint16 DelayMs, uint16 *SentCount, CFE_MSG_FcnCode_t *LastFcnCode)
{
    int32  status;
    uint16 delay_ms = SP006_NormalizeDelay(DelayMs, 0);

    status = SP006_SendNoArgsCmd(CAM_CMD_MID, SP006_CAM_HWLIB_CAPTURE_CC); // FC = 29
    if (status != CFE_SUCCESS)
    {
        return status;
    }

    *SentCount   = 1;
    *LastFcnCode = SP006_CAM_HWLIB_CAPTURE_CC;

    if (delay_ms > 0)
    {
        OS_TaskDelay((uint32)delay_ms);
    }

    status = SP006_SendNoArgsCmd(CAM_CMD_MID, SP006_CAM_HWLIB_READ_CC); // FC = 31，中间跳过了30
    if (status == CFE_SUCCESS)
    {
        *SentCount   = 2;
        *LastFcnCode = SP006_CAM_HWLIB_READ_CC;
    }

    return status;
}

static int32 SP006_RunCamCollectionInterrupt(int32 InterruptArg, uint16 DelayMs, uint16 *SentCount,
                                             CFE_MSG_FcnCode_t *LastFcnCode)
{
    int32             status;
    uint16            delay_ms = SP006_NormalizeDelay(DelayMs, SP006_DEFAULT_CAM_INTERRUPT_DELAY_MS);
    CFE_MSG_FcnCode_t interrupt_cc;

    switch (InterruptArg) // 支持的中断
    {
        case SP006_CAM_STOP_CC:
        case SP006_CAM_PAUSE_CC:
        case SP006_CAM_TIMEOUT_CC:
        case SP006_CAM_LOW_VOLTAGE_CC:
            interrupt_cc = (CFE_MSG_FcnCode_t)InterruptArg;
            break;

        default:
            interrupt_cc = SP006_DEFAULT_CAM_INTERRUPT_CC;
            break;
    }

    status = SP006_SendNoArgsCmd(CAM_CMD_MID, SP006_CAM_EXP3_CC);
    if (status != CFE_SUCCESS)
    {
        return status;
    }

    *SentCount   = 1;
    *LastFcnCode = SP006_CAM_EXP3_CC;

    OS_TaskDelay((uint32)delay_ms);

    status = SP006_SendNoArgsCmd(CAM_CMD_MID, interrupt_cc); // 检测在cam采集状态下，允不允许中断
    if (status == CFE_SUCCESS)
    {
        *SentCount   = 2;
        *LastFcnCode = interrupt_cc;
    }

    return status;
}

static int32 SP006_SendRwSetTorque(int32 WheelArg, int32 TorqueArg)
{
    SP006_RwCmd_t AbuseCmd;
    uint8         wheel;
    int16         torque;

    wheel  = (WheelArg < 0) ? SP006_DEFAULT_RW_WHEEL : (uint8)WheelArg;
    torque = (TorqueArg == 0) ? SP006_DEFAULT_RW_TORQUE_UNITS : (int16)TorqueArg;

    memset(&AbuseCmd, 0, sizeof(AbuseCmd));
    CFE_MSG_Init(CFE_MSG_PTR(AbuseCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_RW_APP_CMD_MID), sizeof(AbuseCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&AbuseCmd, SP006_GENERIC_RW_APP_SET_TORQUE_CC);

    AbuseCmd.wheel_number = wheel;
    AbuseCmd.data         = torque;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&AbuseCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&AbuseCmd, true);
}

static int32 SP006_SendThrusterPercentage(int32 ThrusterArg, int32 PercentageArg)
{
    SP006_ThrusterPercentageCmd_t AbuseCmd;
    uint8                         thruster;
    uint8                         percentage;

    thruster   = (ThrusterArg < 0) ? SP006_DEFAULT_THRUSTER_NUMBER : (uint8)ThrusterArg;
    percentage = (PercentageArg == 0) ? SP006_DEFAULT_THRUSTER_PERCENTAGE : (uint8)PercentageArg;

    memset(&AbuseCmd, 0, sizeof(AbuseCmd));
    CFE_MSG_Init(CFE_MSG_PTR(AbuseCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_THRUSTER_CMD_MID), sizeof(AbuseCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&AbuseCmd, SP006_GENERIC_THRUSTER_PERCENTAGE_CC);

    AbuseCmd.ThrusterNumber = thruster;
    AbuseCmd.Percentage     = percentage;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&AbuseCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&AbuseCmd, true);
}

static void SP006_FillResult(SP006_ProfileResult_t *Result, CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode,
                             uint16 TargetId, uint16 SentCount, int32 Status)
{
    if (Result != NULL)
    {
        Result->MsgId     = MsgId;
        Result->FcnCode   = FcnCode;
        Result->TargetId  = TargetId;
        Result->SentCount = SentCount;
        Result->Status    = Status;
    }
}
