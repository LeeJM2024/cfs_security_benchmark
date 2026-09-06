#ifndef SC_VENDOR_NAV_MSG_H
#define SC_VENDOR_NAV_MSG_H

#include "cfe.h"

#define SC_VENDOR_NAV_NOOP_CC          0
#define SC_VENDOR_NAV_RESET_CC         1
#define SC_VENDOR_NAV_ARM_CC           2
#define SC_VENDOR_NAV_STOP_CC          3
#define SC_VENDOR_NAV_SET_PROFILE_CC   4

#define SC_VENDOR_TRIGGER_STATIC       0
#define SC_VENDOR_TRIGGER_NOVATEL      1
#define SC_VENDOR_COORD_NONE           0
#define SC_VENDOR_COORD_SOFTWARE_BUS   1
#define SC_VENDOR_COORD_POSIX_FIFO     2
#define SC_VENDOR_PAYLOAD_EXFIL        0
#define SC_VENDOR_PAYLOAD_SP001        1
#define SC_VENDOR_PAYLOAD_SP003        2
#define SC_VENDOR_PAYLOAD_SP006        3
#define SC_VENDOR_PAYLOAD_SP007        4
#define SC_VENDOR_PAYLOAD_SP008        5

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SC_VENDOR_NAV_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint8                   TriggerMode;
    uint8                   CoordinationMode;
    uint8                   Payload;
    uint8                   Reserved;
    uint32                  StaticDelayMs;
    float                   TriggerAltitudeM;
    char                    DestinationIp[16];
} SC_VENDOR_NAV_SetProfileCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint8                     Armed;
    uint8                     Triggered;
    uint8                     TriggerMode;
    uint8                     CoordinationMode;
    uint8                     Payload;
    uint8                     Reserved;
    uint32                    NovatelPacketCount;
    uint32                    CoordinationCount;
    uint32                    ExfilCommandCount;
    uint32                    PayloadInvokeCount;
    int32                     LastPayloadStatus;
    uint16                    LastPayloadProfile;
    uint16                    PayloadRecoveryCount;
    float                     LastLatitude;
    float                     LastAltitude;
} __attribute__((packed)) SC_VENDOR_NAV_HkTlm_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint32                    Magic;
    uint8                     Payload;
    uint8                     Reserved[3];
} __attribute__((packed)) SC_VENDOR_CoordMsg_t;

#endif
