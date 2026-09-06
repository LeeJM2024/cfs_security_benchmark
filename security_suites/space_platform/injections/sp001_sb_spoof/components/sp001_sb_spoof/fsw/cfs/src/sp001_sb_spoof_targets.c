#include "sp001_sb_spoof_targets.h"

#include <string.h>

#include "cf_msg.h"
#include "cf_msgids.h"
#include "cfe_es_msg.h"
#include "cfe_es_msgids.h"
#include "cfe_tbl_msg.h"
#include "cfe_tbl_msgids.h"
#include "ds_msg.h"
#include "ds_msgdefs.h"
#include "ds_msgids.h"
#include "ds_platform_cfg.h"
#include "ds_extern_typedefs.h"
#include "fm_msg.h"
#include "fm_msgdefs.h"
#include "fm_msgids.h"
#include "generic_adcs_msg.h"
#include "generic_adcs_msgids.h"
#include "generic_css_msg.h"
#include "generic_css_msgids.h"
#include "generic_eps_msg.h"
#include "generic_eps_msgids.h"
#include "generic_fss_msg.h"
#include "generic_fss_msgids.h"
#include "generic_imu_msg.h"
#include "generic_imu_msgids.h"
#include "generic_mag_msg.h"
#include "generic_mag_msgids.h"
#include "generic_radio_msg.h"
#include "generic_radio_msgids.h"
#include "generic_reaction_wheel_msg.h"
#include "generic_reaction_wheel_msgids.h"
#include "generic_star_tracker_msg.h"
#include "generic_star_tracker_msgids.h"
#include "generic_thruster_msg.h"
#include "generic_thruster_msgids.h"
#include "generic_torquer_msg.h"
#include "generic_torquer_msgids.h"
#include "lc_msg.h"
#include "lc_msgdefs.h"
#include "lc_msgids.h"
#include "novatel_oem615_msg.h"
#include "novatel_oem615_msgids.h"
#include "sc_msg.h"
#include "sc_msgdefs.h"
#include "sc_msgids.h"
#include "sch_msg.h"
#include "sch_msgdefs.h"
#include "sch_msgids.h"
#include "to_lab_msg.h"
#include "to_lab_msgids.h"

#define SP001_EPS_STATE_OFF 0x00
#define SP001_EPS_STATE_ON  0xAA

#define SP001_FM_SAFE_DIR       "/cf/sp001_safe_dir"
#define SP001_FM_DELETE_FILE    "/cf/sp001_delete_me.tmp"
#define SP001_FM_DELETE_ALL_DIR "/cf/sp001_delete_all"
#define SP001_FM_PERM_FILE      "/cf/sp001_perm.tmp"
#define SP001_FM_DELETE_DIR     "/cf/sp001_delete_dir"
#define SP001_TBL_LOAD_FILE     "/cf/sp001_tbl.tbl"
#define SP001_TBL_NAME          "SP001_SB_SPOOF.Config"
#define SP001_TO_LAB_IP         "127.0.0.1"

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint32                  DeviceCfg;
} SP001_DeviceConfigCmd_t;

static void  SP001_CopyPath(char *Dest, size_t DestSize, const char *Src);
static const char *SP001_SelectEsAppName(int32 Selector);
static int32 SP001_SendNoArgsCmd(CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode);

static int32 SP001_SpoofAdcsSetMode(uint8 Mode);
static int32 SP001_SpoofAdcsMomentumManagement(uint8 MomentumManagement);
static int32 SP001_SpoofTorquerPercentOn(uint8 TrqNum, uint8 Direction, uint8 PercentOn);
static int32 SP001_SpoofTorquerAllPercentOn(uint8 Direction, uint8 PercentOn);
static int32 SP001_SpoofRwSetTorque(uint8 WheelNumber, int16 Torque);
static int32 SP001_SpoofRwDeviceCmd(CFE_MSG_FcnCode_t FcnCode, uint8 WheelNumber);
static int32 SP001_SpoofEpsSwitch(uint8 SwitchNumber, uint8 State);
static int32 SP001_SpoofDsSetAppState(uint16 EnableState);
static int32 SP001_SpoofDsSetDestState(uint16 FileTableIndex, uint16 EnableState);
static int32 SP001_SpoofFmCreateDir(void);
static int32 SP001_SpoofFmDeleteFile(void);
static int32 SP001_SpoofFmDeleteAll(void);
static int32 SP001_SpoofFmSetFilePerm(uint32 Mode);
static int32 SP001_SpoofFmDeleteDir(void);
static int32 SP001_SpoofThrusterPercentage(uint8 ThrusterNumber, uint8 Percentage);
static int32 SP001_SpoofRadioConfig(uint32 DeviceCfg);
static int32 SP001_SpoofRadioProximity(uint16 ScId, uint8 Pattern);
static int32 SP001_SpoofNovatelLog(uint8 LogType, uint8 PeriodOption);
static int32 SP001_SpoofNovatelUnlog(uint8 LogType);
static int32 SP001_SpoofDeviceConfig(CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode, uint32 DeviceCfg);
static int32 SP001_SpoofToLabOutputEnable(void);
static int32 SP001_SpoofToLabRemovePkt(CFE_SB_MsgId_Atom_t Stream);
static int32 SP001_SpoofSchEntry(CFE_MSG_FcnCode_t FcnCode, uint16 SlotNumber, uint16 EntryNumber);
static int32 SP001_SpoofSchGroup(CFE_MSG_FcnCode_t FcnCode, uint8 GroupNumber, uint32 MultiGroupMask);
static int32 SP001_SpoofScRts(CFE_MSG_FcnCode_t FcnCode, uint16 RtsId);
static int32 SP001_SpoofLcSetState(uint16 NewState);
static int32 SP001_SpoofLcSetApState(uint16 ApNumber, uint16 NewState);
static int32 SP001_SpoofCfChannel(CFE_MSG_FcnCode_t FcnCode, uint8 Channel);
static int32 SP001_SpoofTblLoad(void);
static int32 SP001_SpoofTblValidate(void);
static int32 SP001_SpoofTblActivate(void);
static int32 SP001_SpoofEsAppControl(CFE_MSG_FcnCode_t FcnCode, int32 AppSelector);

int32 SP001_RunProfile(const SP001_RunProfileCmd_t *Cmd)
{
    switch (Cmd->ProfileId)
    {
        case SP001_PROFILE_ADCS_SET_MODE:
            return SP001_SpoofAdcsSetMode((uint8)Cmd->Arg1);

        case SP001_PROFILE_ADCS_MOMENTUM_MANAGEMENT:
            return SP001_SpoofAdcsMomentumManagement((uint8)Cmd->Arg1);

        case SP001_PROFILE_TORQUER_ENABLE:
            return SP001_SendNoArgsCmd(GENERIC_TORQUER_CMD_MID, GENERIC_TORQUER_ENABLE_CC);

        case SP001_PROFILE_TORQUER_DISABLE:
            return SP001_SendNoArgsCmd(GENERIC_TORQUER_CMD_MID, GENERIC_TORQUER_DISABLE_CC);

        case SP001_PROFILE_TORQUER_PERCENT_ON:
            return SP001_SpoofTorquerPercentOn((uint8)Cmd->Arg1, (uint8)Cmd->Arg2, (uint8)Cmd->Arg3);

        case SP001_PROFILE_TORQUER_ALL_PERCENT_ON:
            return SP001_SpoofTorquerAllPercentOn((uint8)Cmd->Arg1, (uint8)Cmd->Arg2);

        case SP001_PROFILE_RW_SET_TORQUE:
            return SP001_SpoofRwSetTorque((uint8)Cmd->Arg1, (int16)Cmd->Arg2);

        case SP001_PROFILE_RW_ENABLE:
            return SP001_SpoofRwDeviceCmd(GENERIC_RW_ENABLE_CC, (uint8)Cmd->Arg1);

        case SP001_PROFILE_RW_DISABLE:
            return SP001_SpoofRwDeviceCmd(GENERIC_RW_DISABLE_CC, (uint8)Cmd->Arg1);

        case SP001_PROFILE_EPS_SWITCH:
            return SP001_SpoofEpsSwitch((uint8)Cmd->Arg1, (uint8)Cmd->Arg2);

        case SP001_PROFILE_DS_SET_APP_STATE:
            return SP001_SpoofDsSetAppState((uint16)Cmd->Arg1);

        case SP001_PROFILE_DS_SET_DEST_STATE:
            return SP001_SpoofDsSetDestState((uint16)Cmd->Arg1, (uint16)Cmd->Arg2);

        case SP001_PROFILE_FM_CREATE_DIR:
            return SP001_SpoofFmCreateDir();

        case SP001_PROFILE_FM_DELETE_FILE:
            return SP001_SpoofFmDeleteFile();

        case SP001_PROFILE_FM_DELETE_ALL:
            return SP001_SpoofFmDeleteAll();

        case SP001_PROFILE_FM_SET_FILE_PERM:
            return SP001_SpoofFmSetFilePerm((uint32)Cmd->Arg1);

        case SP001_PROFILE_FM_DELETE_DIR:
            return SP001_SpoofFmDeleteDir();

        case SP001_PROFILE_THRUSTER_ENABLE:
            return SP001_SendNoArgsCmd(GENERIC_THRUSTER_CMD_MID, GENERIC_THRUSTER_ENABLE_CC);

        case SP001_PROFILE_THRUSTER_DISABLE:
            return SP001_SendNoArgsCmd(GENERIC_THRUSTER_CMD_MID, GENERIC_THRUSTER_DISABLE_CC);

        case SP001_PROFILE_THRUSTER_PERCENTAGE:
            return SP001_SpoofThrusterPercentage((uint8)Cmd->Arg1, (uint8)Cmd->Arg2);

        case SP001_PROFILE_RADIO_CONFIG:
            return SP001_SpoofRadioConfig((uint32)Cmd->Arg1);

        case SP001_PROFILE_RADIO_PROXIMITY:
            return SP001_SpoofRadioProximity((uint16)Cmd->Arg1, (uint8)Cmd->Arg2);

        case SP001_PROFILE_NOVATEL_ENABLE:
            return SP001_SendNoArgsCmd(NOVATEL_OEM615_CMD_MID, NOVATEL_OEM615_ENABLE_CC);

        case SP001_PROFILE_NOVATEL_DISABLE:
            return SP001_SendNoArgsCmd(NOVATEL_OEM615_CMD_MID, NOVATEL_OEM615_DISABLE_CC);

        case SP001_PROFILE_NOVATEL_LOG:
            return SP001_SpoofNovatelLog((uint8)Cmd->Arg1, (uint8)Cmd->Arg2);

        case SP001_PROFILE_NOVATEL_UNLOG:
            return SP001_SpoofNovatelUnlog((uint8)Cmd->Arg1);

        case SP001_PROFILE_NOVATEL_UNLOGALL:
            return SP001_SendNoArgsCmd(NOVATEL_OEM615_CMD_MID, NOVATEL_OEM615_UNLOGALL_CC);

        case SP001_PROFILE_NOVATEL_SERIALCONFIG:
            return SP001_SendNoArgsCmd(NOVATEL_OEM615_CMD_MID, NOVATEL_OEM615_SERIALCONFIG_CC);

        case SP001_PROFILE_IMU_ENABLE:
            return SP001_SendNoArgsCmd(GENERIC_IMU_CMD_MID, GENERIC_IMU_ENABLE_CC);

        case SP001_PROFILE_IMU_DISABLE:
            return SP001_SendNoArgsCmd(GENERIC_IMU_CMD_MID, GENERIC_IMU_DISABLE_CC);

        case SP001_PROFILE_IMU_CONFIG:
            return SP001_SpoofDeviceConfig(GENERIC_IMU_CMD_MID, GENERIC_IMU_CONFIG_CC, (uint32)Cmd->Arg1);

        case SP001_PROFILE_MAG_ENABLE:
            return SP001_SendNoArgsCmd(GENERIC_MAG_CMD_MID, GENERIC_MAG_ENABLE_CC);

        case SP001_PROFILE_MAG_DISABLE:
            return SP001_SendNoArgsCmd(GENERIC_MAG_CMD_MID, GENERIC_MAG_DISABLE_CC);

        case SP001_PROFILE_CSS_ENABLE:
            return SP001_SendNoArgsCmd(GENERIC_CSS_CMD_MID, GENERIC_CSS_ENABLE_CC);

        case SP001_PROFILE_CSS_DISABLE:
            return SP001_SendNoArgsCmd(GENERIC_CSS_CMD_MID, GENERIC_CSS_DISABLE_CC);

        case SP001_PROFILE_FSS_ENABLE:
            return SP001_SendNoArgsCmd(GENERIC_FSS_CMD_MID, GENERIC_FSS_ENABLE_CC);

        case SP001_PROFILE_FSS_DISABLE:
            return SP001_SendNoArgsCmd(GENERIC_FSS_CMD_MID, GENERIC_FSS_DISABLE_CC);

        case SP001_PROFILE_STAR_TRACKER_ENABLE:
            return SP001_SendNoArgsCmd(GENERIC_STAR_TRACKER_CMD_MID, GENERIC_STAR_TRACKER_ENABLE_CC);

        case SP001_PROFILE_STAR_TRACKER_DISABLE:
            return SP001_SendNoArgsCmd(GENERIC_STAR_TRACKER_CMD_MID, GENERIC_STAR_TRACKER_DISABLE_CC);

        case SP001_PROFILE_STAR_TRACKER_CONFIG:
            return SP001_SpoofDeviceConfig(GENERIC_STAR_TRACKER_CMD_MID, GENERIC_STAR_TRACKER_CONFIG_CC,
                                           (uint32)Cmd->Arg1);

        case SP001_PROFILE_TO_LAB_OUTPUT_ENABLE:
            return SP001_SpoofToLabOutputEnable();

        case SP001_PROFILE_TO_LAB_REMOVE_PKT:
            return SP001_SpoofToLabRemovePkt((CFE_SB_MsgId_Atom_t)Cmd->Arg1);

        case SP001_PROFILE_TO_LAB_REMOVE_ALL:
            return SP001_SendNoArgsCmd(TO_LAB_CMD_MID, TO_LAB_REMOVE_ALL_PKT_CC);

        case SP001_PROFILE_SCH_ENABLE_ENTRY:
            return SP001_SpoofSchEntry(SCH_ENABLE_CC, (uint16)Cmd->Arg1, (uint16)Cmd->Arg2);

        case SP001_PROFILE_SCH_DISABLE_ENTRY:
            return SP001_SpoofSchEntry(SCH_DISABLE_CC, (uint16)Cmd->Arg1, (uint16)Cmd->Arg2);

        case SP001_PROFILE_SCH_ENABLE_GROUP:
            return SP001_SpoofSchGroup(SCH_ENABLE_GROUP_CC, (uint8)Cmd->Arg1, (uint32)Cmd->Arg2);

        case SP001_PROFILE_SCH_DISABLE_GROUP:
            return SP001_SpoofSchGroup(SCH_DISABLE_GROUP_CC, (uint8)Cmd->Arg1, (uint32)Cmd->Arg2);

        case SP001_PROFILE_SC_START_RTS:
            return SP001_SpoofScRts(SC_START_RTS_CC, (uint16)Cmd->Arg1);

        case SP001_PROFILE_SC_STOP_RTS:
            return SP001_SpoofScRts(SC_STOP_RTS_CC, (uint16)Cmd->Arg1);

        case SP001_PROFILE_SC_ENABLE_RTS:
            return SP001_SpoofScRts(SC_ENABLE_RTS_CC, (uint16)Cmd->Arg1);

        case SP001_PROFILE_SC_DISABLE_RTS:
            return SP001_SpoofScRts(SC_DISABLE_RTS_CC, (uint16)Cmd->Arg1);

        case SP001_PROFILE_LC_SET_STATE:
            return SP001_SpoofLcSetState((uint16)Cmd->Arg1);

        case SP001_PROFILE_LC_SET_AP_STATE:
            return SP001_SpoofLcSetApState((uint16)Cmd->Arg1, (uint16)Cmd->Arg2);

        case SP001_PROFILE_CF_FREEZE:
            return SP001_SpoofCfChannel(CF_FREEZE_CC, (uint8)Cmd->Arg1);

        case SP001_PROFILE_CF_THAW:
            return SP001_SpoofCfChannel(CF_THAW_CC, (uint8)Cmd->Arg1);

        case SP001_PROFILE_CF_ENABLE_ENGINE:
            return SP001_SendNoArgsCmd(CF_CMD_MID, CF_ENABLE_ENGINE_CC);

        case SP001_PROFILE_CF_DISABLE_ENGINE:
            return SP001_SendNoArgsCmd(CF_CMD_MID, CF_DISABLE_ENGINE_CC);

        case SP001_PROFILE_TBL_LOAD:
            return SP001_SpoofTblLoad();

        case SP001_PROFILE_TBL_VALIDATE:
            return SP001_SpoofTblValidate();

        case SP001_PROFILE_TBL_ACTIVATE:
            return SP001_SpoofTblActivate();

        case SP001_PROFILE_ES_STOP_APP:
            return SP001_SpoofEsAppControl(CFE_ES_STOP_APP_CC, Cmd->Arg1);

        case SP001_PROFILE_ES_RESTART_APP:
            return SP001_SpoofEsAppControl(CFE_ES_RESTART_APP_CC, Cmd->Arg1);

        default:
            return CFE_STATUS_BAD_COMMAND_CODE;
    }
}

static void SP001_CopyPath(char *Dest, size_t DestSize, const char *Src)
{
    if (DestSize > 0)
    {
        memset(Dest, 0, DestSize);
        strncpy(Dest, Src, DestSize - 1);
    }
}

static const char *SP001_SelectEsAppName(int32 Selector)
{
    switch (Selector)
    {
        case 1:
            return "FM";
        case 2:
            return "DS";
        case 3:
            return "TO_LAB_APP";
        case 4:
            return "SCH";
        case 5:
            return "SC";
        case 6:
            return "LC";
        case 7:
            return "CF";
        case 8:
            return "ADCS";
        case 9:
            return "EPS";
        case 10:
            return "RW";
        case 11:
            return "TORQUER";
        case 12:
            return "THRUSTER";
        default:
            return "FM";
    }
}

static int32 SP001_SendNoArgsCmd(CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode)
{
    SP001_NoArgsCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(MsgId), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);

    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofAdcsSetMode(uint8 Mode)
{
    Generic_ADCS_Mode_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_ADCS_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_ADCS_SET_MODE_CC);

    SpoofCmd.Mode = Mode;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofAdcsMomentumManagement(uint8 MomentumManagement)
{
    Generic_ADCS_MomentumManagement_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_ADCS_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_ADCS_SET_MOMENTUM_MANAGEMENT_CC);

    SpoofCmd.MomentumManagement = MomentumManagement;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofTorquerPercentOn(uint8 TrqNum, uint8 Direction, uint8 PercentOn)
{
    GENERIC_TORQUER_Percent_On_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_TORQUER_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_TORQUER_CONFIG_CC);

    SpoofCmd.TrqNum    = TrqNum;
    SpoofCmd.Direction = Direction;
    SpoofCmd.PercentOn = PercentOn;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofTorquerAllPercentOn(uint8 Direction, uint8 PercentOn)
{
    GENERIC_TORQUER_All_Percent_On_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_TORQUER_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_TORQUER_CONFIG_ALL_CC);

    SpoofCmd.Direction_0 = Direction;
    SpoofCmd.PercentOn_0 = PercentOn;
    SpoofCmd.Direction_1 = Direction;
    SpoofCmd.PercentOn_1 = PercentOn;
    SpoofCmd.Direction_2 = Direction;
    SpoofCmd.PercentOn_2 = PercentOn;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofRwSetTorque(uint8 WheelNumber, int16 Torque)
{
    GENERIC_RW_Cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_RW_APP_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_RW_APP_SET_TORQUE_CC);

    SpoofCmd.wheel_number = WheelNumber;
    SpoofCmd.data         = Torque;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofRwDeviceCmd(CFE_MSG_FcnCode_t FcnCode, uint8 WheelNumber)
{
    GENERIC_RW_Cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_RW_APP_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);

    SpoofCmd.wheel_number = WheelNumber;
    SpoofCmd.data         = 0;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofEpsSwitch(uint8 SwitchNumber, uint8 State)
{
    GENERIC_EPS_Switch_cmd_t SpoofCmd;

    if (State != SP001_EPS_STATE_ON)
    {
        State = SP001_EPS_STATE_OFF;
    }

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_EPS_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_EPS_SWITCH_CC);

    SpoofCmd.SwitchNumber = SwitchNumber;
    SpoofCmd.State        = State;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofDsSetAppState(uint16 EnableState)
{
    DS_AppStateCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CommandHeader), CFE_SB_ValueToMsgId(DS_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, DS_SET_APP_STATE_CC);

    SpoofCmd.Payload.EnableState = (EnableState == DS_ENABLED) ? DS_ENABLED : DS_DISABLED;
    SpoofCmd.Payload.Padding     = 0;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofDsSetDestState(uint16 FileTableIndex, uint16 EnableState)
{
    DS_DestStateCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CommandHeader), CFE_SB_ValueToMsgId(DS_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, DS_SET_DEST_STATE_CC);

    SpoofCmd.Payload.FileTableIndex = FileTableIndex;
    SpoofCmd.Payload.EnableState    = (EnableState == DS_ENABLED) ? DS_ENABLED : DS_DISABLED;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofFmCreateDir(void)
{
    FM_CreateDirCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(FM_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FM_CREATE_DIR_CC);
    SP001_CopyPath(SpoofCmd.Directory, sizeof(SpoofCmd.Directory), SP001_FM_SAFE_DIR);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofFmDeleteFile(void)
{
    FM_DeleteFileCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(FM_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FM_DELETE_CC);
    SP001_CopyPath(SpoofCmd.Filename, sizeof(SpoofCmd.Filename), SP001_FM_DELETE_FILE);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofFmDeleteAll(void)
{
    FM_DeleteAllCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(FM_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FM_DELETE_ALL_CC);
    SP001_CopyPath(SpoofCmd.Directory, sizeof(SpoofCmd.Directory), SP001_FM_DELETE_ALL_DIR);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofFmSetFilePerm(uint32 Mode)
{
    FM_SetPermCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(FM_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FM_SET_FILE_PERM_CC);

    SP001_CopyPath(SpoofCmd.FileName, sizeof(SpoofCmd.FileName), SP001_FM_PERM_FILE);
    SpoofCmd.Mode = Mode;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofFmDeleteDir(void)
{
    FM_DeleteDirCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(FM_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FM_DELETE_DIR_CC);
    SP001_CopyPath(SpoofCmd.Directory, sizeof(SpoofCmd.Directory), SP001_FM_DELETE_DIR);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofThrusterPercentage(uint8 ThrusterNumber, uint8 Percentage)
{
    GENERIC_THRUSTER_Percentage_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_THRUSTER_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_THRUSTER_PERCENTAGE_CC);

    SpoofCmd.ThrusterNumber = ThrusterNumber;
    SpoofCmd.Percentage     = Percentage;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofRadioConfig(uint32 DeviceCfg)
{
    GENERIC_RADIO_Config_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_RADIO_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_RADIO_CONFIG_CC);

    SpoofCmd.DeviceCfg = DeviceCfg;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofRadioProximity(uint16 ScId, uint8 Pattern)
{
    GENERIC_RADIO_Proximity_cmd_t SpoofCmd;
    SP001_NoArgsCmd_t             InnerMsg;

    memset(&SpoofCmd, Pattern, sizeof(SpoofCmd));
    memset(&InnerMsg, 0, sizeof(InnerMsg));

    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(GENERIC_RADIO_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, GENERIC_RADIO_PROXIMITY_CC);

    CFE_MSG_Init(CFE_MSG_PTR(InnerMsg.CmdHeader), CFE_SB_ValueToMsgId(CFE_ES_CMD_MID), sizeof(InnerMsg));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&InnerMsg, CFE_ES_NOOP_CC);

    SpoofCmd.SCID = ScId;
    if (sizeof(InnerMsg) <= sizeof(SpoofCmd.Payload))
    {
        memcpy(SpoofCmd.Payload, &InnerMsg, sizeof(InnerMsg));
    }

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofNovatelLog(uint8 LogType, uint8 PeriodOption)
{
    NOVATEL_OEM615_Log_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(NOVATEL_OEM615_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, NOVATEL_OEM615_LOG_CC);

    SpoofCmd.LogType      = LogType;
    SpoofCmd.PeriodOption = PeriodOption;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofNovatelUnlog(uint8 LogType)
{
    NOVATEL_OEM615_Unlog_cmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(NOVATEL_OEM615_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, NOVATEL_OEM615_UNLOG_CC);

    SpoofCmd.LogType = LogType;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofDeviceConfig(CFE_SB_MsgId_Atom_t MsgId, CFE_MSG_FcnCode_t FcnCode, uint32 DeviceCfg)
{
    SP001_DeviceConfigCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(MsgId), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);

    SpoofCmd.DeviceCfg = DeviceCfg;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofToLabOutputEnable(void)
{
    TO_LAB_EnableOutputCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(TO_LAB_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, TO_LAB_OUTPUT_ENABLE_CC);
    SP001_CopyPath(SpoofCmd.Payload.dest_IP, sizeof(SpoofCmd.Payload.dest_IP), SP001_TO_LAB_IP);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofToLabRemovePkt(CFE_SB_MsgId_Atom_t Stream)
{
    TO_LAB_RemovePacketCmd_t SpoofCmd;

    if (Stream == 0)
    {
        Stream = GENERIC_ADCS_HK_TLM_MID;
    }

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(TO_LAB_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, TO_LAB_REMOVE_PKT_CC);

    SpoofCmd.Payload.Stream = CFE_SB_ValueToMsgId(Stream);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofSchEntry(CFE_MSG_FcnCode_t FcnCode, uint16 SlotNumber, uint16 EntryNumber)
{
    SCH_EntryCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(SCH_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);

    SpoofCmd.SlotNumber  = SlotNumber;
    SpoofCmd.EntryNumber = EntryNumber;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofSchGroup(CFE_MSG_FcnCode_t FcnCode, uint8 GroupNumber, uint32 MultiGroupMask)
{
    SCH_GroupCmd_t SpoofCmd;

    if (GroupNumber == 0)
    {
        GroupNumber = 1;
    }
    if ((MultiGroupMask & 0x00FFFFFF) == 0)
    {
        MultiGroupMask = 1;
    }

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(SCH_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);

    SpoofCmd.GroupData = ((uint32)GroupNumber << 24) | (MultiGroupMask & 0x00FFFFFF);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofScRts(CFE_MSG_FcnCode_t FcnCode, uint16 RtsId)
{
    SC_RtsCmd_t SpoofCmd;

    if (RtsId == 0)
    {
        RtsId = 1;
    }

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(SC_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);

    SpoofCmd.RtsId   = RtsId;
    SpoofCmd.Padding = 0;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofLcSetState(uint16 NewState)
{
    LC_SetLCState_t SpoofCmd;

    if (NewState != LC_STATE_ACTIVE && NewState != LC_STATE_PASSIVE && NewState != LC_STATE_DISABLED)
    {
        NewState = LC_STATE_DISABLED;
    }

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(LC_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, LC_SET_LC_STATE_CC);

    SpoofCmd.NewLCState = NewState;
    SpoofCmd.Padding    = 0;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofLcSetApState(uint16 ApNumber, uint16 NewState)
{
    LC_SetAPState_t SpoofCmd;

    if (NewState != LC_APSTATE_ACTIVE && NewState != LC_APSTATE_PASSIVE && NewState != LC_APSTATE_DISABLED)
    {
        NewState = LC_APSTATE_DISABLED;
    }

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CmdHeader), CFE_SB_ValueToMsgId(LC_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, LC_SET_AP_STATE_CC);

    SpoofCmd.APNumber   = ApNumber;
    SpoofCmd.NewAPState = NewState;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofCfChannel(CFE_MSG_FcnCode_t FcnCode, uint8 Channel)
{
    CF_UnionArgsCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.cmd_header), CFE_SB_ValueToMsgId(CF_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);

    SpoofCmd.data.byte[0] = Channel;

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofTblLoad(void)
{
    CFE_TBL_LoadCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, CFE_TBL_LOAD_CC);
    SP001_CopyPath(SpoofCmd.Payload.LoadFilename, sizeof(SpoofCmd.Payload.LoadFilename), SP001_TBL_LOAD_FILE);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofTblValidate(void)
{
    CFE_TBL_ValidateCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, CFE_TBL_VALIDATE_CC);

    SpoofCmd.Payload.ActiveTableFlag = 0;
    SP001_CopyPath(SpoofCmd.Payload.TableName, sizeof(SpoofCmd.Payload.TableName), SP001_TBL_NAME);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofTblActivate(void)
{
    CFE_TBL_ActivateCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, CFE_TBL_ACTIVATE_CC);
    SP001_CopyPath(SpoofCmd.Payload.TableName, sizeof(SpoofCmd.Payload.TableName), SP001_TBL_NAME);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}

static int32 SP001_SpoofEsAppControl(CFE_MSG_FcnCode_t FcnCode, int32 AppSelector)
{
    CFE_ES_AppNameCmd_t SpoofCmd;

    memset(&SpoofCmd, 0, sizeof(SpoofCmd));
    CFE_MSG_Init(CFE_MSG_PTR(SpoofCmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_ES_CMD_MID), sizeof(SpoofCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&SpoofCmd, FcnCode);
    SP001_CopyPath(SpoofCmd.Payload.Application, sizeof(SpoofCmd.Payload.Application),
                   SP001_SelectEsAppName(AppSelector));

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SpoofCmd);
    return CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SpoofCmd, true);
}
