#include "cfe.h"
#include "cfe_tbl_filedef.h"
#include "fm_msg.h"
#include "fm_platform_cfg.h"

/*
 * Valid-but-dangerous FM.FreeSpace image for SP004.
 *
 * The default NOS3 FM table monitors /ram and /cf.  This image marks every
 * monitor entry unused, so a normal FM_GET_FREE_SPACE command stops reporting
 * those storage health points after the table is loaded and activated.
 */
FM_MonitorTable_t SP004_FM_MonitorTableBad = {
    {
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
        {.Type = FM_MonitorTableEntry_Type_UNUSED, .Enabled = false, .Name = ""},
    }};

CFE_TBL_FILEDEF(SP004_FM_MonitorTableBad, FM.FreeSpace, SP004 FM off, sp004_fm_bad.tbl)
