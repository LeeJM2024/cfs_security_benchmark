#include "sp007_resource_exhaustion_app.h"
#include "sp007_resource_exhaustion_profiles.h"

#include <stdio.h>
#include <string.h>

static uint32 SP007_ClampU32(uint32 Value, uint32 DefaultValue, uint32 MaxValue);
static bool   SP007_StopRequested(void);
static bool   SP007_DurationExpired(OS_time_t StartTime, uint32 DurationMs, uint32 *FallbackElapsedMs,
                                     uint32 FallbackStepMs);
static void   SP007_MarkProfileComplete(int32 Status);
static int32  SP007_StartCpuWorkers(const SP007_StartProfileCmd_t *Cmd);
static int32  SP007_RunCpuBusy(const SP007_StartProfileCmd_t *Cmd);
static void   SP007_CpuWorkerTask(void);
static int32  SP007_RunSbFlood(const SP007_StartProfileCmd_t *Cmd);
static int32  SP007_RunEvsStorm(const SP007_StartProfileCmd_t *Cmd);
static int32  SP007_RunCfFill(const SP007_StartProfileCmd_t *Cmd);
static int32  SP007_RunOsalQueueExhaust(const SP007_StartProfileCmd_t *Cmd);

static uint32 SP007_ClampU32(uint32 Value, uint32 DefaultValue, uint32 MaxValue)
{
    uint32 Result = (Value == 0) ? DefaultValue : Value;

    if (Result > MaxValue)
    {
        Result = MaxValue;
    }

    return Result;
}

static bool SP007_StopRequested(void)
{
    return (SP007_AppData.HkTelemetryPkt.StopRequested != 0) ||
           (SP007_AppData.RunStatus != CFE_ES_RunStatus_APP_RUN);
}

static bool SP007_DurationExpired(OS_time_t StartTime, uint32 DurationMs, uint32 *FallbackElapsedMs,
                                  uint32 FallbackStepMs)
{
    OS_time_t NowTime;

    if (OS_GetLocalTime(&NowTime) == OS_SUCCESS)
    {
        return OS_TimeGetTotalMilliseconds(OS_TimeSubtract(NowTime, StartTime)) >= DurationMs;
    }

    if (FallbackElapsedMs != NULL)
    {
        *FallbackElapsedMs += FallbackStepMs;
        return *FallbackElapsedMs >= DurationMs;
    }

    return false;
}

void SP007_ResetProfileState(void)
{
    uint32 i;

    SP007_AppData.ProfileTaskRunning = false;

    for (i = 0; i < SP007_MAX_CPU_WORKERS; i++)
    {
        SP007_AppData.CpuWorkerRunning[i] = false;
    }

    for (i = 0; i < SP007_MAX_HELD_PIPES; i++)
    {
        SP007_AppData.HeldPipes[i]     = CFE_SB_INVALID_PIPE;
        SP007_AppData.HeldPipeInUse[i] = false;
    }

    for (i = 0; i < SP007_MAX_HELD_QUEUES; i++)
    {
        SP007_AppData.HeldQueues[i]     = OS_OBJECT_ID_UNDEFINED;
        SP007_AppData.HeldQueueInUse[i] = false;
    }
}

int32 SP007_StartProfile(const SP007_StartProfileCmd_t *Cmd)
{
    int32 status;

    if (Cmd == NULL)
    {
        return CFE_ES_BAD_ARGUMENT;
    }

    if (SP007_AppData.ProfileTaskRunning || SP007_AppData.HkTelemetryPkt.Active != 0)
    {
        return CFE_STATUS_REQUEST_ALREADY_PENDING;
    }

    switch (Cmd->ProfileId)
    {
        case SP007_PROFILE_CPU_BUSY_STARVATION:
        case SP007_PROFILE_SB_TELEMETRY_FLOOD:
        case SP007_PROFILE_EVS_EVENT_STORM:
        case SP007_PROFILE_CF_STORAGE_FILL:
        case SP007_PROFILE_OSAL_QUEUE_EXHAUST:
            break;
        default:
            return CFE_ES_BAD_ARGUMENT;
    }

    SP007_AppData.ActiveCmd                      = *Cmd;
    SP007_AppData.HkTelemetryPkt.Active          = 1;
    SP007_AppData.HkTelemetryPkt.StopRequested   = 0;
    SP007_AppData.HkTelemetryPkt.ActiveProfileId = Cmd->ProfileId;

    if (Cmd->ProfileId == SP007_PROFILE_CPU_BUSY_STARVATION)
    {
        status = SP007_StartCpuWorkers(Cmd);
        if (status != CFE_SUCCESS)
        {
            SP007_AppData.HkTelemetryPkt.Active          = 0;
            SP007_AppData.HkTelemetryPkt.ActiveProfileId = SP007_PROFILE_NONE;
            SP007_AppData.HkTelemetryPkt.LastApiStatus   = status;
            return status;
        }
    }

    SP007_AppData.ProfileTaskRunning = true;

    status = CFE_ES_CreateChildTask(&SP007_AppData.ProfileTaskId, "SP007_PROFILE", SP007_ProfileTask, 0,
                                    SP007_PROFILE_STACK_SIZE, SP007_PROFILE_PRIORITY, 0);
    if (status != CFE_SUCCESS)
    {
        SP007_StopProfile();
        SP007_AppData.ProfileTaskRunning             = false;
        SP007_AppData.HkTelemetryPkt.Active          = 0;
        SP007_AppData.HkTelemetryPkt.ActiveProfileId = SP007_PROFILE_NONE;
        SP007_AppData.HkTelemetryPkt.LastApiStatus   = status;
    }

    return status;
}

void SP007_StopProfile(void)
{
    SP007_AppData.HkTelemetryPkt.StopRequested = 1;
    SP007_AppData.HkTelemetryPkt.StopCount++;
}

void SP007_CleanupResources(void)
{
    uint32 i;
    int32  status;

    SP007_AppData.HkTelemetryPkt.StopRequested = 1;

    for (i = 0; i < SP007_MAX_CPU_WORKERS; i++)
    {
        SP007_AppData.CpuWorkerRunning[i] = false;
    }

    for (i = 0; i < SP007_MAX_HELD_PIPES; i++)
    {
        if (SP007_AppData.HeldPipeInUse[i])
        {
            status = CFE_SB_DeletePipe(SP007_AppData.HeldPipes[i]);
            SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
            SP007_AppData.HeldPipes[i]                 = CFE_SB_INVALID_PIPE;
            SP007_AppData.HeldPipeInUse[i]             = false;
        }
    }

    for (i = 0; i < SP007_MAX_HELD_QUEUES; i++)
    {
        if (SP007_AppData.HeldQueueInUse[i])
        {
            status = OS_QueueDelete(SP007_AppData.HeldQueues[i]);
            SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
            SP007_AppData.HeldQueues[i]                = OS_OBJECT_ID_UNDEFINED;
            SP007_AppData.HeldQueueInUse[i]            = false;
        }
    }

    status = OS_remove(SP007_FILL_FILE_PATH);
    SP007_AppData.HkTelemetryPkt.LastApiStatus = status;

    SP007_AppData.HkTelemetryPkt.HeldPipeCount  = 0;
    SP007_AppData.HkTelemetryPkt.HeldQueueCount = 0;
    SP007_AppData.HkTelemetryPkt.FilePresent    = 0;
    SP007_AppData.HkTelemetryPkt.CleanupCount++;
}

void SP007_ProfileTask(void)
{
    int32                    status = CFE_SUCCESS;
    SP007_StartProfileCmd_t  cmd;

    cmd = SP007_AppData.ActiveCmd;

    switch (cmd.ProfileId)
    {
        case SP007_PROFILE_CPU_BUSY_STARVATION:
            SP007_AppData.HkTelemetryPkt.LastResourceId = SP007_RESOURCE_CPU;
            status = SP007_RunCpuBusy(&cmd);
            break;

        case SP007_PROFILE_SB_TELEMETRY_FLOOD:
            SP007_AppData.HkTelemetryPkt.LastResourceId = SP007_RESOURCE_SB;
            status = SP007_RunSbFlood(&cmd);
            break;

        case SP007_PROFILE_EVS_EVENT_STORM:
            SP007_AppData.HkTelemetryPkt.LastResourceId = SP007_RESOURCE_EVS;
            status = SP007_RunEvsStorm(&cmd);
            break;

        case SP007_PROFILE_CF_STORAGE_FILL:
            SP007_AppData.HkTelemetryPkt.LastResourceId = SP007_RESOURCE_CF;
            status = SP007_RunCfFill(&cmd);
            break;

        case SP007_PROFILE_OSAL_QUEUE_EXHAUST:
            SP007_AppData.HkTelemetryPkt.LastResourceId = SP007_RESOURCE_OSAL;
            status = SP007_RunOsalQueueExhaust(&cmd);
            break;

        default:
            status = CFE_ES_BAD_ARGUMENT;
            break;
    }

    SP007_MarkProfileComplete(status);
    CFE_ES_ExitChildTask();
}

static void SP007_MarkProfileComplete(int32 Status)
{
    SP007_AppData.HkTelemetryPkt.LastStatus       = Status;
    SP007_AppData.HkTelemetryPkt.LastApiStatus    = Status;
    SP007_AppData.HkTelemetryPkt.Active           = 0;
    SP007_AppData.HkTelemetryPkt.ActiveProfileId  = SP007_PROFILE_NONE;
    SP007_AppData.ProfileTaskRunning              = false;

    if (Status == CFE_SUCCESS || SP007_AppData.HkTelemetryPkt.StopRequested != 0)
    {
        SP007_AppData.HkTelemetryPkt.ProfilesCompleted++;
        CFE_EVS_SendEvent(SP007_PROFILE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "SP007: profile %u completed status=0x%08X", (unsigned int)SP007_AppData.ActiveCmd.ProfileId,
                          (unsigned int)Status);
    }
    else
    {
        CFE_EVS_SendEvent(SP007_PROFILE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "SP007: profile %u ended with error status=0x%08X",
                          (unsigned int)SP007_AppData.ActiveCmd.ProfileId, (unsigned int)Status);
    }
}

static int32 SP007_StartCpuWorkers(const SP007_StartProfileCmd_t *Cmd)
{
    uint32 worker_count = SP007_ClampU32((uint32)Cmd->Arg1, SP007_DEFAULT_CPU_WORKERS, SP007_MAX_CPU_WORKERS);
    uint32 i;
    uint32 created = 0;
    int32  status = CFE_SUCCESS;
    char   task_name[16];

    for (i = 0; i < worker_count; i++)
    {
        snprintf(task_name, sizeof(task_name), "SP007_CPU_%lu", (unsigned long)i);
        SP007_AppData.CpuWorkerRunning[i] = true;
        status = CFE_ES_CreateChildTask(&SP007_AppData.CpuTaskId[i], task_name, SP007_CpuWorkerTask, 0,
                                        SP007_CPU_STACK_SIZE, SP007_CPU_PRIORITY, 0);
        if (status == CFE_SUCCESS)
        {
            SP007_AppData.HkTelemetryPkt.CpuWorkerCount++;
            SP007_AppData.HkTelemetryPkt.WorkerTaskCount++;
            created++;
        }
        else
        {
            SP007_AppData.CpuWorkerRunning[i] = false;
            SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
            CFE_EVS_SendEvent(SP007_PROFILE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "SP007: CPU worker %lu create failed RC=0x%08X", (unsigned long)i,
                              (unsigned int)status);
            break;
        }
    }

    if (created == 0)
    {
        return status;
    }

    CFE_EVS_SendEvent(SP007_WORKER_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "SP007: CPU busy workers created count=%lu duration_ms=%lu yield_loops=%lu",
                      (unsigned long)created,
                      (unsigned long)SP007_ClampU32(Cmd->DurationMs, SP007_DEFAULT_DURATION_MS, SP007_MAX_DURATION_MS),
                      (unsigned long)SP007_ClampU32(Cmd->RateOrYield, SP007_DEFAULT_CPU_YIELD_LOOPS,
                                                    SP007_MAX_CPU_YIELD_LOOPS));

    return CFE_SUCCESS;
}

static int32 SP007_RunCpuBusy(const SP007_StartProfileCmd_t *Cmd)
{
    uint32    duration_ms = SP007_ClampU32(Cmd->DurationMs, SP007_DEFAULT_DURATION_MS, SP007_MAX_DURATION_MS);
    uint32    fallback_ms = 0;
    OS_time_t start_time;

    OS_GetLocalTime(&start_time);

    while (!SP007_StopRequested() && !SP007_DurationExpired(start_time, duration_ms, &fallback_ms, 25))
    {
        OS_TaskDelay(25);
    }

    SP007_StopProfile();

    return CFE_SUCCESS;
}

static void SP007_CpuWorkerTask(void)
{
    uint32          duration_ms = SP007_ClampU32(SP007_AppData.ActiveCmd.DurationMs, SP007_DEFAULT_DURATION_MS,
                                                 SP007_MAX_DURATION_MS);
    uint32          yield_loops = SP007_ClampU32(SP007_AppData.ActiveCmd.RateOrYield, SP007_DEFAULT_CPU_YIELD_LOOPS,
                                                 SP007_MAX_CPU_YIELD_LOOPS);
    uint32          fallback_ms = 0;
    OS_time_t       start_time;
    volatile uint32 spin;

    OS_GetLocalTime(&start_time);

    while (!SP007_StopRequested() && !SP007_DurationExpired(start_time, duration_ms, &fallback_ms, 1))
    {
        for (spin = 0; spin < yield_loops; spin++)
        {
        }
        OS_TaskDelay(1);
    }

    CFE_ES_ExitChildTask();
}

static int32 SP007_RunSbFlood(const SP007_StartProfileCmd_t *Cmd)
{
    uint32 limit    = SP007_ClampU32(Cmd->Limit, SP007_DEFAULT_FLOOD_COUNT, SP007_MAX_FLOOD_COUNT);
    uint32 delay_ms = SP007_ClampU32(Cmd->RateOrYield, 0, 1000);
    uint32 i;
    int32  status   = CFE_SUCCESS;

    for (i = 0; i < sizeof(SP007_AppData.FloodTelemetryPkt.Payload); i++)
    {
        SP007_AppData.FloodTelemetryPkt.Payload[i] = (uint8)(i & 0xFF);
    }

    for (i = 0; i < limit && !SP007_StopRequested(); i++)
    {
        SP007_AppData.FloodTelemetryPkt.Sequence++;
        SP007_AppData.FloodTelemetryPkt.ProfileId = SP007_PROFILE_SB_TELEMETRY_FLOOD;
        CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&SP007_AppData.FloodTelemetryPkt);
        status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&SP007_AppData.FloodTelemetryPkt, true);
        if (status == CFE_SUCCESS)
        {
            SP007_AppData.HkTelemetryPkt.SbTransmitCount++;
        }
        else
        {
            SP007_AppData.HkTelemetryPkt.SbTransmitErrorCount++;
            SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
        }

        if ((i % 128) == 0)
        {
            OS_TaskDelay(delay_ms);
        }
    }

    return status;
}

static int32 SP007_RunEvsStorm(const SP007_StartProfileCmd_t *Cmd)
{
    uint32 limit    = SP007_ClampU32(Cmd->Limit, SP007_DEFAULT_EVENT_COUNT, SP007_MAX_EVENT_COUNT);
    uint32 delay_ms = SP007_ClampU32(Cmd->RateOrYield, 0, 1000);
    uint32 i;
    int32  status   = CFE_SUCCESS;

    for (i = 0; i < limit && !SP007_StopRequested(); i++)
    {
        status = CFE_EVS_SendEvent(SP007_EVS_STORM_BASE_EID + (i % SP007_EVS_STORM_EVENT_COUNT),
                                   CFE_EVS_EventType_INFORMATION, "SP007: EVS storm event %lu/%lu",
                                   (unsigned long)(i + 1), (unsigned long)limit);
        if (status == CFE_SUCCESS)
        {
            SP007_AppData.HkTelemetryPkt.EvsSendCount++;
        }
        else
        {
            SP007_AppData.HkTelemetryPkt.EvsSendErrorCount++;
            SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
        }

        if ((i % 64) == 0)
        {
            OS_TaskDelay(delay_ms);
        }
    }

    return status;
}

static int32 SP007_RunCfFill(const SP007_StartProfileCmd_t *Cmd)
{
    uint32    target_kb = SP007_ClampU32(Cmd->Limit, SP007_DEFAULT_FILE_KB, SP007_MAX_FILE_KB);
    uint32    chunks    = target_kb;
    uint32    i;
    int32     status;
    osal_id_t fd;
    uint8     buffer[SP007_FILE_CHUNK_BYTES];

    for (i = 0; i < sizeof(buffer); i++)
    {
        buffer[i] = (uint8)(0xA5 ^ (i & 0xFF));
    }

    status = OS_OpenCreate(&fd, SP007_FILL_FILE_PATH, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_READ_WRITE);
    if (status != OS_SUCCESS)
    {
        SP007_AppData.HkTelemetryPkt.FileWriteErrorCount++;
        SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
        return status;
    }

    SP007_AppData.HkTelemetryPkt.FilePresent = 1;

    for (i = 0; i < chunks && !SP007_StopRequested(); i++)
    {
        status = OS_write(fd, buffer, sizeof(buffer));
        if (status == (int32)sizeof(buffer))
        {
            SP007_AppData.HkTelemetryPkt.FileBytesWritten += sizeof(buffer);
        }
        else
        {
            SP007_AppData.HkTelemetryPkt.FileWriteErrorCount++;
            SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
            break;
        }

        if ((i % 256) == 0)
        {
            OS_TaskDelay(1);
        }
    }

    OS_close(fd);
    return (status == (int32)sizeof(buffer) || SP007_StopRequested()) ? CFE_SUCCESS : status;
}

static int32 SP007_RunOsalQueueExhaust(const SP007_StartProfileCmd_t *Cmd)
{
    uint32 hold_count  = SP007_ClampU32(Cmd->Limit, SP007_DEFAULT_HOLD_COUNT, SP007_MAX_HELD_PIPES);
    uint32 queue_count = SP007_ClampU32((uint32)Cmd->Arg1, SP007_MAX_DIRECT_QUEUE_HOLD, SP007_MAX_DIRECT_QUEUE_HOLD);
    uint32 i;
    int32  status      = CFE_SUCCESS;
    int32  last_status = CFE_SUCCESS;

    for (i = 0; i < hold_count && !SP007_StopRequested(); i++)
    {
        char pipe_name[16];

        snprintf(pipe_name, sizeof(pipe_name), "SP7P%02lu", (unsigned long)i);
        status = CFE_SB_CreatePipe(&SP007_AppData.HeldPipes[i], 1, pipe_name);
        SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
        if (status == CFE_SUCCESS)
        {
            SP007_AppData.HeldPipeInUse[i] = true;
            SP007_AppData.HkTelemetryPkt.HeldPipeCount++;
        }
        else
        {
            last_status = status;
            break;
        }
    }

    for (i = 0; i < queue_count && !SP007_StopRequested(); i++)
    {
        char queue_name[16];

        snprintf(queue_name, sizeof(queue_name), "SP7Q%02lu", (unsigned long)i);
        status = OS_QueueCreate(&SP007_AppData.HeldQueues[i], queue_name, OSAL_BLOCKCOUNT_C(4), OSAL_SIZE_C(16), 0);
        SP007_AppData.HkTelemetryPkt.LastApiStatus = status;
        if (status == OS_SUCCESS)
        {
            SP007_AppData.HeldQueueInUse[i] = true;
            SP007_AppData.HkTelemetryPkt.HeldQueueCount++;
        }
        else
        {
            last_status = status;
            break;
        }
    }

    return last_status;
}
