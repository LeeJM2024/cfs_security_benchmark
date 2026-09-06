#include "cfe.h"
#include "cfe_tbl_filedef.h"
#include "ds_platform_cfg.h"
#include "ds_extern_typedefs.h"
#include "ds_msg.h"

/* Valid but unsafe DS.FILE_TBL image: route event/HK storage to a small benchmark file. */
DS_DestFileTable_t SP004_DS_DestFileTableBad = {
    .Descriptor = "SP004 DS file tbl",
    .File = {
        [0] = {.Movename = DS_EMPTY_STRING,
               .Pathname = "/cf",
               .Basename = "sp004ds",
               .Extension = ".bad",
               .FileNameType = DS_BY_COUNT,
               .EnableState = DS_ENABLED,
               .MaxFileSize = 1024,
               .MaxFileAge = 60,
               .SequenceCount = 9000},
        [1] = {.Movename = DS_EMPTY_STRING,
               .Pathname = "/cf",
               .Basename = "sp004hk",
               .Extension = ".bad",
               .FileNameType = DS_BY_COUNT,
               .EnableState = DS_DISABLED,
               .MaxFileSize = 1024,
               .MaxFileAge = 60,
               .SequenceCount = 9001},
    }};

CFE_TBL_FILEDEF(SP004_DS_DestFileTableBad, DS.FILE_TBL, SP004 DS file, sp004_ds_file.tbl)
