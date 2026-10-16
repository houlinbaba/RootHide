#include "credential_diagnostics.h"
#include "roothide_stage.h"
#include <errno.h>
#include <stddef.h>

static _Thread_local struct rh_failure_scope *activeFailure;

void rh_failure_begin(struct rh_failure_scope *scope, const char *operation, int pid)
{
    *scope = (struct rh_failure_scope){ .previous = activeFailure, .operation = operation, .pid = pid };
    activeFailure = scope;
}

void rh_failure_note(const char *phase, const char *domain, long long raw, int result)
{
    if (!result || !activeFailure || activeFailure->phase) return;
    activeFailure->phase = phase;
    activeFailure->domain = domain;
    activeFailure->raw = raw;
    activeFailure->result = result;
    // For non-POSIX domains this is context only, not the error's domain/code.
    activeFailure->observed_errno = errno;
}

int rh_failure_end(struct rh_failure_scope *scope, const char *boundary,
                   const char *domain, long long raw, int result)
{
    int savedErrno = errno;
    rh_failure_note(boundary, domain, raw, result);
    activeFailure = scope->previous;
    if (result) {
        roothide_stage_file_log(ROOTHIDE_BOOTSTRAP_STAGE_LOG_PATH,
            "privilege.first_failure operation=%s pid=%d boundary=%s origin=%s domain=%s raw=%lld observed_errno=%d converted=%d result=%d",
            scope->operation, scope->pid, boundary, scope->phase, scope->domain,
            scope->raw, scope->observed_errno, scope->result, result);
    }
    errno = savedErrno;
    return result;
}
