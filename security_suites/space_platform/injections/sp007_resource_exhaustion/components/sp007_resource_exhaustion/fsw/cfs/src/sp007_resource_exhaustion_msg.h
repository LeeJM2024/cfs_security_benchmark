#ifndef _SP007_RESOURCE_EXHAUSTION_MSG_H_
#define _SP007_RESOURCE_EXHAUSTION_MSG_H_

#include "cfe.h"

#define SP007_NOOP_CC          0
#define SP007_RESET_CC         1
#define SP007_START_PROFILE_CC 2
#define SP007_STOP_PROFILE_CC  3
#define SP007_CLEANUP_CC       4

#define SP007_PROFILE_NONE                0
#define SP007_PROFILE_CPU_BUSY_STARVATION 1
#define SP007_PROFILE_SB_TELEMETRY_FLOOD  2
#define SP007_PROFILE_EVS_EVENT_STORM     3
#define SP007_PROFILE_CF_STORAGE_FILL     4
#define SP007_PROFILE_OSAL_QUEUE_EXHAUST  5

#define SP007_DEFAULT_DURATION_MS      5000
#define SP007_MAX_DURATION_MS          30000
#define SP007_DEFAULT_CPU_WORKERS      6
#define SP007_MAX_CPU_WORKERS          8
#define SP007_DEFAULT_CPU_YIELD_LOOPS  2000000
#define SP007_MAX_CPU_YIELD_LOOPS      50000000
#define SP007_DEFAULT_FLOOD_COUNT      2000
#define SP007_MAX_FLOOD_COUNT          200000
#define SP007_DEFAULT_EVENT_COUNT      1000
#define SP007_MAX_EVENT_COUNT          50000
#define SP007_DEFAULT_FILE_KB          4096
#define SP007_MAX_FILE_KB              65536
#define SP007_DEFAULT_HOLD_COUNT       40
#define SP007_MAX_HELD_PIPES           48
#define SP007_MAX_HELD_QUEUES          48
#define SP007_MAX_DIRECT_QUEUE_HOLD    24
#define SP007_FILE_CHUNK_BYTES         1024
#define SP007_FLOOD_PAYLOAD_BYTES      96
#define SP007_FILL_FILE_PATH           "/cf/sp007_fill.dat"

#define SP007_STATUS_IDLE              0
#define SP007_STATUS_ACTIVE            1
#define SP007_STATUS_STOP_REQUESTED    2
#define SP007_STATUS_COMPLETED         3
#define SP007_STATUS_ERROR             4

#define SP007_RESOURCE_NONE            0
#define SP007_RESOURCE_CPU             1
#define SP007_RESOURCE_SB              2
#define SP007_RESOURCE_EVS             3
#define SP007_RESOURCE_CF              4
#define SP007_RESOURCE_OSAL            5

#ifndef OS_OBJECT_ID_UNDEFINED
#define OS_OBJECT_ID_UNDEFINED ((osal_id_t){0})
#endif

#ifndef OS_OBJECT_ID_RESERVED
#define OS_OBJECT_ID_RESERVED ((osal_id_t){0xFFFFFFFF})
#endif

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SP007_NoArgsCmd_t;

typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint16                  ProfileId;
    uint16                  Flags;
    uint32                  DurationMs;
    uint32                  RateOrYield;
    uint32                  Limit;
    int32                   Arg1;
    int32                   Arg2;
    int32                   Arg3;
    int32                   Arg4;
} __attribute__((packed)) SP007_StartProfileCmd_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint16                    ActiveProfileId;
    uint16                    LastProfileId;
    uint16                    LastResourceId;
    uint16                    LastFlags;
    uint32                    LastDurationMs;
    uint32                    LastRateOrYield;
    uint32                    LastLimit;
    int32                     LastStatus;
    uint32                    ProfilesStarted;
    uint32                    ProfilesCompleted;
    uint32                    StopCount;
    uint32                    CleanupCount;
    uint32                    WorkerTaskCount;
    uint32                    CpuWorkerCount;
    uint32                    SbTransmitCount;
    uint32                    SbTransmitErrorCount;
    uint32                    EvsSendCount;
    uint32                    EvsSendErrorCount;
    uint32                    FileBytesWritten;
    uint32                    FileWriteErrorCount;
    uint32                    HeldPipeCount;
    uint32                    HeldQueueCount;
    int32                     LastApiStatus;
    uint8                     Active;
    uint8                     StopRequested;
    uint8                     FilePresent;
    uint8                     Reserved;
} __attribute__((packed)) SP007_HkTlm_t;

#define SP007_HK_TLM_LEN sizeof(SP007_HkTlm_t)

typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint32                    Sequence;
    uint32                    ProfileId;
    uint8                     Payload[SP007_FLOOD_PAYLOAD_BYTES];
} __attribute__((packed)) SP007_FloodTlm_t;

#define SP007_FLOOD_TLM_LEN sizeof(SP007_FloodTlm_t)

#endif
