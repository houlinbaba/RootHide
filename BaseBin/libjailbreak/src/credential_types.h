#ifndef RH_CREDENTIAL_TYPES_H
#define RH_CREDENTIAL_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define RH_CREDENTIAL_GROUPS 16
#define RH_CREDENTIAL_HELPER_ARG "--roothide-credential-helper"
#define RH_CREDENTIAL_HELPER_ENV "ROOTHIDE_CREDENTIAL_HELPER"
#define RH_CREDENTIAL_MAIN_ONLY_ENV "ROOTHIDE_CREDENTIAL_MAIN_ONLY"
#define RH_CREDENTIAL_READY_MAGIC 0x52484331u

struct rh_credential {
    uint32_t uid, ruid, svuid, gid, rgid, svgid;
    uint16_t ngroups;
    uint32_t groups[RH_CREDENTIAL_GROUPS];
};

struct rh_credential_ready {
    uint32_t magic;
    int32_t error;
};

static inline bool rh_credential_valid(const struct rh_credential *c)
{
    if (!c || c->ngroups == 0 || c->ngroups > RH_CREDENTIAL_GROUPS) return false;
    // -1 means "unchanged" to the identity syscalls; it is not a valid request.
    if (c->uid == UINT32_MAX || c->ruid == UINT32_MAX || c->svuid == UINT32_MAX ||
        c->gid == UINT32_MAX || c->rgid == UINT32_MAX || c->svgid == UINT32_MAX ||
        c->groups[0] != c->gid) return false;
    for (unsigned i = 0; i < c->ngroups; i++) {
        if (c->groups[i] == UINT32_MAX) return false;
    }
    return true;
}

static inline bool rh_credential_equal(const struct rh_credential *a, const struct rh_credential *b)
{
    return a->uid == b->uid && a->ruid == b->ruid && a->svuid == b->svuid &&
           a->gid == b->gid && a->rgid == b->rgid && a->svgid == b->svgid &&
           a->ngroups == b->ngroups &&
           memcmp(a->groups, b->groups, a->ngroups * sizeof(a->groups[0])) == 0;
}

#endif
