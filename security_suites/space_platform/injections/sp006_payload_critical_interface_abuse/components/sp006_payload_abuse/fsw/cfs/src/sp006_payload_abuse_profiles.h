#ifndef _SP006_PAYLOAD_ABUSE_PROFILES_H_
#define _SP006_PAYLOAD_ABUSE_PROFILES_H_

#include "cfe.h"
#include "sp006_payload_abuse_msg.h"

typedef struct
{
    CFE_SB_MsgId_Atom_t MsgId;
    CFE_MSG_FcnCode_t   FcnCode;
    uint16              TargetId;
    uint16              SentCount;
    int32               Status;
} SP006_ProfileResult_t;

int32 SP006_RunProfile(const SP006_RunProfileCmd_t *Cmd, SP006_ProfileResult_t *Result);

#endif
