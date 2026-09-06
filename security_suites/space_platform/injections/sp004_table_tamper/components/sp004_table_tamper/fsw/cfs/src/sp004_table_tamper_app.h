#ifndef _SP004_TABLE_TAMPER_APP_H_
#define _SP004_TABLE_TAMPER_APP_H_

#include "cfe.h"

#include "sp004_table_tamper_events.h"
#include "sp004_table_tamper_msg.h"
#include "sp004_table_tamper_msgids.h"
#include "sp004_table_tamper_perfids.h"
#include "sp004_table_tamper_profiles.h"

#define SP004_APP_NAME   "SP004"
#define SP004_PIPE_DEPTH 16

typedef struct
{
    CFE_SB_PipeId_t   CmdPipe;
    CFE_MSG_Message_t *MsgPtr;
    uint32            RunStatus;
    SP004_HkTlm_t     HkTelemetryPkt;
} SP004_AppData_t;

extern SP004_AppData_t SP004_AppData;

void SP004_AppMain(void);

#endif
