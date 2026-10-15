#ifndef RH_CREDENTIAL_HELPER_H
#define RH_CREDENTIAL_HELPER_H

#include "credential_types.h"
#include <sys/syscall.h>
#include <errno.h>

// The dyld entry uses raw syscalls: libc/TLS and the application have not
// initialized yet. The application entry supplies the same negative-errno ABI.
#ifndef RH_CREDENTIAL_SYSCALL
#error Define RH_CREDENTIAL_SYSCALL(number, arg1, arg2, arg3) before including this header
#endif

static inline bool rh_credential_number(const char *s, uint32_t *out)
{
    if (!s || !*s) return false;
    uint32_t n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        unsigned digit = (unsigned)(*s - '0');
        if (n > (UINT32_MAX - digit) / 10) return false;
        n = n * 10 + digit;
    }
    *out = n;
    return true;
}

static inline int rh_credential_parse(int argc, char *const argv[], struct rh_credential *c)
{
    uint32_t count;
    if (argc < 10 || !rh_credential_number(argv[8], &count) ||
        count == 0 || count > RH_CREDENTIAL_GROUPS || argc != (int)(9 + count)) return EINVAL;
    memset(c, 0, sizeof(*c));
    uint32_t *fields[] = { &c->uid, &c->ruid, &c->svuid, &c->gid, &c->rgid, &c->svgid };
    for (unsigned i = 0; i < 6; i++) {
        if (!rh_credential_number(argv[2 + i], fields[i])) return EINVAL;
    }
    c->ngroups = (uint16_t)count;
    for (unsigned i = 0; i < count; i++) {
        if (!rh_credential_number(argv[9 + i], &c->groups[i])) return EINVAL;
    }
    return rh_credential_valid(c) ? 0 : EINVAL;
}

static inline int rh_credential_apply(const struct rh_credential *c)
{
    if (!rh_credential_valid(c)) return EINVAL;
    long r = RH_CREDENTIAL_SYSCALL(SYS_geteuid, 0, 0, 0);
    if (r != 0) return EPERM;
    // Set real/saved IDs while privileged. Drop effective uid last, retaining
    // the requested saved uid (Dopamine needs 0 while its UI runs as mobile).
    r = RH_CREDENTIAL_SYSCALL(SYS_setregid, c->rgid, c->svgid, 0);
    if (r < 0) return (int)-r;
    // XNU preserves the old saved ID when it matches either argument. A
    // second call with an unchanged real ID makes the requested saved ID
    // explicit, including real=0/saved=mobile.
    r = RH_CREDENTIAL_SYSCALL(SYS_setregid, UINT32_MAX, c->svgid, 0);
    if (r < 0) return (int)-r;
    r = RH_CREDENTIAL_SYSCALL(SYS_setgroups, c->ngroups, (uintptr_t)c->groups, 0);
    if (r < 0) return (int)-r;
    r = RH_CREDENTIAL_SYSCALL(SYS_setegid, c->gid, 0, 0);
    if (r < 0) return (int)-r;
    // If the effective UID is outside the requested real/saved pair, retain
    // it temporarily as the real UID so the final seteuid is permitted.
    // Restoring real later preserves saved only when real == saved.
    bool temporaryReal = c->uid != c->ruid && c->uid != c->svuid && c->svuid != 0;
    if (temporaryReal && c->ruid != c->svuid) return ENOTSUP;
    r = RH_CREDENTIAL_SYSCALL(SYS_setreuid, temporaryReal ? c->uid : c->ruid, c->svuid, 0);
    if (r < 0) return (int)-r;
    r = RH_CREDENTIAL_SYSCALL(SYS_setreuid, UINT32_MAX, c->svuid, 0);
    if (r < 0) return (int)-r;
    r = RH_CREDENTIAL_SYSCALL(SYS_seteuid, c->uid, 0, 0);
    if (r < 0) return (int)-r;
    if (temporaryReal) {
        r = RH_CREDENTIAL_SYSCALL(SYS_setreuid, c->ruid, UINT32_MAX, 0);
        if (r < 0) return (int)-r;
    }
    if ((uint32_t)RH_CREDENTIAL_SYSCALL(SYS_getuid, 0, 0, 0) != c->ruid ||
        (uint32_t)RH_CREDENTIAL_SYSCALL(SYS_geteuid, 0, 0, 0) != c->uid ||
        (uint32_t)RH_CREDENTIAL_SYSCALL(SYS_getgid, 0, 0, 0) != c->rgid ||
        (uint32_t)RH_CREDENTIAL_SYSCALL(SYS_getegid, 0, 0, 0) != c->gid) return EACCES;
    uint32_t groups[RH_CREDENTIAL_GROUPS] = {0};
    r = RH_CREDENTIAL_SYSCALL(SYS_getgroups, RH_CREDENTIAL_GROUPS, (uintptr_t)groups, 0);
    if (r != c->ngroups) return EACCES;
    // dyldhook has no memcmp import/trampoline. Compare the small group array
    // here without introducing a new dependency before libc initialization.
    for (unsigned i = 0; i < c->ngroups; i++) {
        if (groups[i] != c->groups[i]) return EACCES;
    }
    // The parent verifies saved IDs from the donor's actual kernel credential.
    return 0;
}

static inline bool rh_credential_helper_main(int argc, char *const argv[])
{
    if (argc < 2 || !argv || strcmp(argv[1], RH_CREDENTIAL_HELPER_ARG)) return false;
    struct rh_credential c;
    int error = rh_credential_parse(argc, argv, &c);
    if (!error) error = rh_credential_apply(&c);
    struct rh_credential_ready ready = { RH_CREDENTIAL_READY_MAGIC, error };
    long r;
    do {
        r = RH_CREDENTIAL_SYSCALL(SYS_write, 3, (uintptr_t)&ready, sizeof(ready));
    } while (r == -EINTR);
    // Stay at this single-threaded checkpoint until the parent has taken a
    // reference. EOF also releases us if the parent exits unexpectedly.
    if (r == sizeof(ready) && !error) {
        char token;
        do { r = RH_CREDENTIAL_SYSCALL(SYS_read, 4, (uintptr_t)&token, 1); } while (r == -EINTR);
    }
    RH_CREDENTIAL_SYSCALL(SYS_exit, error ? 1 : 0, 0, 0);
    return true;
}

#endif
