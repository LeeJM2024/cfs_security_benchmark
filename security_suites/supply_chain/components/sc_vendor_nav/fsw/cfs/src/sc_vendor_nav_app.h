#ifndef SC_VENDOR_NAV_APP_H
#define SC_VENDOR_NAV_APP_H

#include "cfe.h"
#include "sc_vendor_nav_events.h"
#include "sc_vendor_nav_msg.h"
#include "sc_vendor_nav_msgids.h"
#include "sc_vendor_nav_perfids.h"

#define SC_VENDOR_NAV_PIPE_DEPTH 16
#define SC_VENDOR_NAV_TIMEOUT_MS 100
#define SC_VENDOR_NAV_TRIGGER_MAGIC 0x53435631U
#define SC_VENDOR_NAV_FIFO_PATH "/tmp/sc_vendor_coord.fifo"

typedef struct
{
    CFE_ES_RunStatus_Enum_t RunStatus;
    CFE_SB_PipeId_t         CmdPipe;
    CFE_MSG_Message_t      *MsgPtr;
    bool                    Armed;
    bool                    Triggered;
    uint8                   TriggerMode;
    uint8                   CoordinationMode;
    uint8                   Payload;
    uint32                  StaticDelayMs;
    uint32                  ElapsedMs;
    float                   TriggerAltitudeM;
    char                    DestinationIp[16];
    SC_VENDOR_NAV_HkTlm_t   HkTelemetryPkt;
} SC_VENDOR_NAV_AppData_t;

extern SC_VENDOR_NAV_AppData_t SC_VENDOR_NAV_AppData;

#endif
