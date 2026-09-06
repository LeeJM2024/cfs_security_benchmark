#include "cfe.h"
#include "cfe_tbl_filedef.h"
#include "sch_platform_cfg.h"
#include "sch_msgdefs.h"
#include "sch_tbldefs.h"

/* Valid but unsafe SCH.SCHED_DEF image: all schedule entries become unused. */
SCH_ScheduleEntry_t SP004_SCH_ScheduleBad[SCH_TABLE_ENTRIES] = {
    {SCH_UNUSED, SCH_ACTIVITY_NONE, 0, 0, 0, 0}};

CFE_TBL_FILEDEF(SP004_SCH_ScheduleBad, SCH.SCHED_DEF, SP004 SCH sched, sp004_sch_sched.tbl)
