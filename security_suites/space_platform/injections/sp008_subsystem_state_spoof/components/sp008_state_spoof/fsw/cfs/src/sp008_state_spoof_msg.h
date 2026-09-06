#ifndef _SP008_STATE_SPOOF_MSG_H_
#define _SP008_STATE_SPOOF_MSG_H_

#include "cfe.h"

#define SP008_NOOP_CC                    0
#define SP008_RESET_CC                   1
#define SP008_START_EPS_HEALTHY_SPOOF_CC 2
#define SP008_STOP_SPOOF_CC              3
#define SP008_START_PROFILE_CC           4

#define SP008_DEFAULT_SPOOF_PERIOD_MS 250
#define SP008_EPS_SWITCH_ON_HEALTHY   0x00AA

#define SP008_PROFILE_NONE                                      0
#define SP008_PROFILE_EPS_HEALTHY_WHILE_REAL_LOW_POWER          1
#define SP008_PROFILE_ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE   2
#define SP008_PROFILE_RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED    3
#define SP008_PROFILE_THRUSTER_ENABLED_WHILE_REAL_DISABLED      4
#define SP008_PROFILE_TORQUER_ACTIVE_WHILE_REAL_DISABLED        5
#define SP008_PROFILE_MGR_SCIENCE_WHILE_REAL_SAFE               6
#define SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL 7

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SP008_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint16                  ProfileId;
    uint16                  Flags;
} __attribute__((packed)) SP008_StartProfileCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint8                     SpoofActive;
    uint8                     Reserved;
    uint16                    ActiveProfileId;
    uint16                    LastProfileId;
    uint16                    LastSpoofedMid;
    uint16                    Reserved16A;
    uint32                    SpoofStartCount;
    uint32                    SpoofStopCount;
    uint32                    ForgedPacketCount;
    uint32                    TransmitErrorCount;
    uint32                    ForgedEpsHkCount;
    uint32                    ForgedAdcsGncCount;
    uint32                    ForgedRwHkCount;
    uint32                    ForgedThrusterHkCount;
    uint32                    ForgedTorquerHkCount;
    uint32                    ForgedMgrHkCount;
    uint32                    ForgedGpsDataCount;
    int32                     LastTransmitStatus;
    uint16                    LastRawBatteryVoltage;
    uint16                    LastRawSolarArrayVoltage;
    uint16                    LastSwitch0Status;
    uint16                    LastAdcsMode;
    uint8                     LastAdcsQValid;
    uint8                     Reserved8;
    double                    LastAdcsQbn[4];
    double                    LastAdcsWbn[3];
} __attribute__((packed)) SP008_HkTlm_t;

#define SP008_HK_TLM_LEN sizeof(SP008_HkTlm_t)

#endif
