#ifndef _SP006_PAYLOAD_ABUSE_APP_H_
#define _SP006_PAYLOAD_ABUSE_APP_H_

#include "cfe.h"

#include "sp006_payload_abuse_events.h"
#include "sp006_payload_abuse_msg.h"
#include "sp006_payload_abuse_msgids.h"
#include "sp006_payload_abuse_perfids.h"
#include "sp006_payload_abuse_profiles.h"

#define SP006_APP_NAME   "SP006"
#define SP006_PIPE_DEPTH 16

typedef struct
{
    CFE_SB_PipeId_t   CmdPipe;
    CFE_MSG_Message_t *MsgPtr;
    uint32            RunStatus;
    SP006_HkTlm_t     HkTelemetryPkt;
} SP006_AppData_t;

extern SP006_AppData_t SP006_AppData;

void SP006_AppMain(void);

#endif
