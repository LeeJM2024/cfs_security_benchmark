#ifndef _SP004_TABLE_TAMPER_PROFILES_H_
#define _SP004_TABLE_TAMPER_PROFILES_H_

#include "cfe.h"
#include "sp004_table_tamper_msg.h"

#define SP004_ACTION_LOAD      0x0001u
#define SP004_ACTION_VALIDATE  0x0002u
#define SP004_ACTION_ACTIVATE  0x0004u
#define SP004_ACTION_DUMP      0x0008u
#define SP004_ACTION_REGISTRY  0x0010u
#define SP004_ACTION_ABORT     0x0020u
#define SP004_ACTION_RESTORE   0x0040u

int32 SP004_RunProfile(const SP004_RunProfileCmd_t *Cmd);

#endif
