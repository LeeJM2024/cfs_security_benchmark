#ifndef SC_VENDOR_DIAG_APP_H
#define SC_VENDOR_DIAG_APP_H

#include "cfe.h"
#include "sc_vendor_diag_events.h"
#include "sc_vendor_diag_msg.h"
#include "sc_vendor_diag_msgids.h"
#include "sc_vendor_diag_perfids.h"

#define SC_VENDOR_DIAG_PIPE_DEPTH 16
#define SC_VENDOR_DIAG_TIMEOUT_MS 100
#define SC_VENDOR_DIAG_TRIGGER_MAGIC 0x53435631U
#define SC_VENDOR_DIAG_FIFO_PATH "/tmp/sc_vendor_coord.fifo"

typedef struct
{
    CFE_ES_RunStatus_Enum_t RunStatus;
    CFE_SB_PipeId_t         CmdPipe;
    CFE_MSG_Message_t      *MsgPtr;
    bool                    Triggered;
    int                     FifoFd;
    SC_VENDOR_DIAG_HkTlm_t  HkTelemetryPkt;
} SC_VENDOR_DIAG_AppData_t;

extern SC_VENDOR_DIAG_AppData_t SC_VENDOR_DIAG_AppData;

#endif
