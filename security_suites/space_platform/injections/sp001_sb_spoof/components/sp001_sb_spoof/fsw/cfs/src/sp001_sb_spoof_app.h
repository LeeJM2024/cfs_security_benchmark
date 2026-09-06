#ifndef _SP001_SB_SPOOF_APP_H_
#define _SP001_SB_SPOOF_APP_H_

#include "cfe.h"

#include "sp001_sb_spoof_events.h"
#include "sp001_sb_spoof_msg.h"
#include "sp001_sb_spoof_msgids.h"
#include "sp001_sb_spoof_perfids.h"
#include "sp001_sb_spoof_targets.h"

#define SP001_PIPE_DEPTH 16

typedef struct
{
    CFE_SB_PipeId_t   CmdPipe;
    CFE_MSG_Message_t *MsgPtr;
    uint32            RunStatus;
    SP001_HkTlm_t     HkTelemetryPkt;
} SP001_AppData_t;

extern SP001_AppData_t SP001_AppData;

void SP001_AppMain(void);

#endif
