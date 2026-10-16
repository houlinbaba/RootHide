#ifndef RH_CREDENTIAL_DIAGNOSTICS_H
#define RH_CREDENTIAL_DIAGNOSTICS_H

// Request-local first failure metadata. Call sites pass constant labels only;
// never pass paths, grants, credential fields, pointers or executable arguments.
struct rh_failure_scope {
    struct rh_failure_scope *previous;
    const char *operation, *phase, *domain;
    int pid, result, observed_errno;
    long long raw;
};
void rh_failure_begin(struct rh_failure_scope *scope, const char *operation, int pid);
void rh_failure_note(const char *phase, const char *domain, long long raw, int result);
int rh_failure_end(struct rh_failure_scope *scope, const char *boundary,
                   const char *domain, long long raw, int result);
#endif
