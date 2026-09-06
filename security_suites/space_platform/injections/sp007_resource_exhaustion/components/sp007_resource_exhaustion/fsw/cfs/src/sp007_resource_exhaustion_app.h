#ifndef _SP007_RESOURCE_EXHAUSTION_APP_H_
#define _SP007_RESOURCE_EXHAUSTION_APP_H_

#include "cfe.h"
#include "sp007_resource_exhaustion_events.h"
#include "sp007_resource_exhaustion_msg.h"
#include "sp007_resource_exhaustion_msgids.h"
#include "sp007_resource_exhaustion_perfids.h"

#define SP007_PIPE_DEPTH          16
#define SP007_PROFILE_STACK_SIZE  32768
#define SP007_PROFILE_PRIORITY    35
#define SP007_CPU_STACK_SIZE      16384
#define SP007_CPU_PRIORITY        45

typedef struct
{
    CFE_ES_RunStatus_Enum_t RunStatus;
    CFE_SB_PipeId_t         CmdPipe;
    CFE_MSG_Message_t      *MsgPtr;
    CFE_ES_TaskId_t         ProfileTaskId;
    CFE_ES_TaskId_t         CpuTaskId[SP007_MAX_CPU_WORKERS];
    CFE_SB_PipeId_t         HeldPipes[SP007_MAX_HELD_PIPES];
    osal_id_t               HeldQueues[SP007_MAX_HELD_QUEUES];
    bool                    HeldPipeInUse[SP007_MAX_HELD_PIPES];
    bool                    HeldQueueInUse[SP007_MAX_HELD_QUEUES];
    SP007_HkTlm_t           HkTelemetryPkt;
    SP007_FloodTlm_t        FloodTelemetryPkt;
    SP007_StartProfileCmd_t ActiveCmd;
    volatile bool           ProfileTaskRunning;
    volatile bool           CpuWorkerRunning[SP007_MAX_CPU_WORKERS];
} SP007_AppData_t;

extern SP007_AppData_t SP007_AppData;

#endif
