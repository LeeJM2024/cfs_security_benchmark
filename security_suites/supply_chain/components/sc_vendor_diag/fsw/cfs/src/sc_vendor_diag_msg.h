#ifndef SC_VENDOR_DIAG_MSG_H
#define SC_VENDOR_DIAG_MSG_H

#include "cfe.h"

#define SC_VENDOR_DIAG_NOOP_CC   0
#define SC_VENDOR_DIAG_RESET_CC  1

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SC_VENDOR_DIAG_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint8                     Triggered;
    uint8                     Reserved;
    uint32                    CoordinationCount;
    uint32                    ExfilCommandCount;
} __attribute__((packed)) SC_VENDOR_DIAG_HkTlm_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint32                    Magic;
    uint8                     Payload;
    uint8                     Reserved[3];
} __attribute__((packed)) SC_VENDOR_DIAG_CoordMsg_t;

#endif
