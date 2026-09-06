#ifndef _SP007_RESOURCE_EXHAUSTION_PROFILES_H_
#define _SP007_RESOURCE_EXHAUSTION_PROFILES_H_

#include "sp007_resource_exhaustion_msg.h"

void  SP007_ProfileTask(void);
int32 SP007_StartProfile(const SP007_StartProfileCmd_t *Cmd);
void  SP007_StopProfile(void);
void  SP007_CleanupResources(void);
void  SP007_ResetProfileState(void);

#endif
