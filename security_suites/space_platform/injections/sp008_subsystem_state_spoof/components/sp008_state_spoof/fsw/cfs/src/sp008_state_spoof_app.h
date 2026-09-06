#ifndef _SP008_STATE_SPOOF_APP_H_
#define _SP008_STATE_SPOOF_APP_H_

#include "cfe.h"
#include "sp008_state_spoof_events.h"
#include "sp008_state_spoof_msg.h"
#include "sp008_state_spoof_msgids.h"
#include "sp008_state_spoof_perfids.h"

#define SP008_PIPE_DEPTH 16

typedef struct
{
    CFE_ES_RunStatus_Enum_t RunStatus;
    CFE_SB_PipeId_t         CmdPipe;
    CFE_MSG_Message_t      *MsgPtr;
    bool                    SpoofActive;
    uint16                  ActiveProfileId;
    SP008_HkTlm_t           HkTelemetryPkt;
} SP008_AppData_t;

extern SP008_AppData_t SP008_AppData;

int32 SP008_BenchmarkStart(uint16 profile_id);
void SP008_BenchmarkStop(void);

#endif
