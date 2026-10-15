#ifndef RH_CREDENTIAL_REFS_H
#define RH_CREDENTIAL_REFS_H

#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>

// XNU 10002: ucred.cr_ref is u_long (64 bit), whereas
// ucred_rw.crw_weak_ref is os_ref_atomic_t (32 bit). Never touch its padding
// or the adjacent crw_cred pointer. A weak release must not retire an object;
// leave that last weak release to XNU to remove it from the credential hash.
// cr_ref counts long-term holders: zero is valid while weak references live.
static inline bool rh_credential_ref32(_Atomic uint32_t *p, bool retain)
{
    uint32_t n = atomic_load(p);
    do {
        if (retain ? (n == 0 || n >= 0x0fffffff) : (n <= 1)) return false;
    } while (!atomic_compare_exchange_weak(p, &n, retain ? n + 1 : n - 1));
    return true;
}

static inline bool rh_credential_ref64(_Atomic uint64_t *p, bool retain)
{
    uint64_t n = atomic_load(p);
    do {
        if (retain ? (n >= 0x0fffffff) : (n == 0)) return false;
    } while (!atomic_compare_exchange_weak(p, &n, retain ? n + 1 : n - 1));
    return true;
}

#endif
