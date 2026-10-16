#ifndef RH_CREDENTIALS_H
#define RH_CREDENTIALS_H

#include "credential_types.h"
#include "credential_diagnostics.h"

int proc_credential_read(uint64_t proc, struct rh_credential *out);
// Pin before bootstrap elevation. Restore consumes the snapshot on success
// and does not spawn a helper, request a persona, or use the injected server.
// A failed release retains its ownership flags for a safe retry.
int proc_credential_snapshot_self(struct rh_credential_snapshot *snapshot);
int proc_credential_restore_self(struct rh_credential_snapshot *snapshot);
// Certificate bootstrap cannot use the private persona entitlement or fork
// from its original sandbox. Borrow launchd's immutable root credential for
// the calling process after stable kernel read/write has been established.
int proc_credential_bootstrap_self(void);
// The caller must serialize identity changes; the target is waiting in its
// check-in/RPC or is the calling application itself. No other set*id operation
// may change its credential concurrently.
int proc_credential_set(uint64_t proc, const char *executable, const struct rh_credential *identity);

#endif
