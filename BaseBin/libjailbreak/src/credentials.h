#ifndef RH_CREDENTIALS_H
#define RH_CREDENTIALS_H

#include "credential_types.h"

int proc_credential_read(uint64_t proc, struct rh_credential *out);
// The caller must serialize identity changes; the target is waiting in its
// check-in/RPC or is the calling application itself. No other set*id operation
// may change its credential concurrently.
int proc_credential_set(uint64_t proc, const char *executable, const struct rh_credential *identity);

#endif
