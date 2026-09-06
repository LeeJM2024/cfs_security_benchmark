#include "cfe.h"
#include "cfe_tbl_filedef.h"
#include "ds_platform_cfg.h"
#include "ds_extern_typedefs.h"
#include "ds_msg.h"
#include "cfe_msgids.h"

/* Valid but unsafe DS.FILTER_TBL image: force selected core packets into file index 0. */
DS_FilterTable_t SP004_DS_FilterTableBad = {
    .Descriptor = "SP004 DS filt tbl",
    .Packet = {
        [0] = {.MessageID = CFE_SB_MSGID_WRAP_VALUE(CFE_EVS_LONG_EVENT_MSG_MID),
               .Filter = {{0, DS_BY_COUNT, 1, 1, 0}}},
        [1] = {.MessageID = CFE_SB_MSGID_WRAP_VALUE(CFE_ES_HK_TLM_MID),
               .Filter = {{0, DS_BY_COUNT, 1, 1, 0}}},
    }};

CFE_TBL_FILEDEF(SP004_DS_FilterTableBad, DS.FILTER_TBL, SP004 DS filt, sp004_ds_filter.tbl)
