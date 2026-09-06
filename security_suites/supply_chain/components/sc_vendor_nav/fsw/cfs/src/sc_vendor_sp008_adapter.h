#ifndef SC_VENDOR_SP008_ADAPTER_H
#define SC_VENDOR_SP008_ADAPTER_H

#include "cfe.h"
#include "sp008_state_spoof_msg.h"

/* Exported by the SP008 implementation compiled into the vendor carrier. */
int32 SP008_BenchmarkStart(uint16 profile_id);
void SP008_BenchmarkStop(void);

#endif
