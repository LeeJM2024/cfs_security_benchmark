#ifndef _SP006_PAYLOAD_ABUSE_MSG_H_
#define _SP006_PAYLOAD_ABUSE_MSG_H_

#include "cfe.h"

#define SP006_NOOP_CC        0
#define SP006_RESET_CC       1
#define SP006_RUN_PROFILE_CC 2

#define SP006_PROFILE_CAM_HWLIB_OUT_OF_ORDER      1
#define SP006_PROFILE_CAM_COLLECTION_INTERRUPT    2
#define SP006_PROFILE_RW_DISABLED_SET_TORQUE      10
#define SP006_PROFILE_THRUSTER_DISABLED_PERCENTAGE 20

#define SP006_DEFAULT_REPEAT_COUNT 1
#define SP006_MAX_REPEAT_COUNT     50
#define SP006_MAX_DELAY_MS         5000

#define SP006_TARGET_NONE     0
#define SP006_TARGET_CAM      1
#define SP006_TARGET_RW       2
#define SP006_TARGET_THRUSTER 3

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SP006_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint16                  ProfileId;
    uint16                  Flags;
    uint16                  RepeatCount;
    uint16                  DelayMs;
    int32                   Arg1;
    int32                   Arg2;
    int32                   Arg3;
    int32                   Arg4;
} __attribute__((packed)) SP006_RunProfileCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint16                    LastProfileId;
    uint16                    LastTargetId;
    uint16                    LastTargetFcnCode;
    uint16                    LastRepeatCount;
    int32                     LastStatus;
    int32                     LastArg1;
    int32                     LastArg2;
    uint32                    ProfilesExecuted;
    uint32                    TargetCommandCount;
    uint32                    TargetCommandErrorCount;
    uint32                    MultiCommandCount;
    CFE_SB_MsgId_Atom_t       LastTargetMsgId;
} __attribute__((packed)) SP006_HkTlm_t;

#define SP006_HK_TLM_LEN sizeof(SP006_HkTlm_t)

#endif
