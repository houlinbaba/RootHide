#ifndef RH_DIAGNOSTIC_LOG_H
#define RH_DIAGNOSTIC_LOG_H

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// Numeric selectors only. This RPC never accepts a client-supplied path.
#define RH_DIAGNOSTIC_LOG_COUNT 7
static inline const char *rh_diagnostic_log_name(uint64_t kind)
{
    static const char *const names[RH_DIAGNOSTIC_LOG_COUNT] = {
        "Dopamine-jailbreakd-stage.log", "Dopamine-jailbreakd-bootstrap.log",
        "Dopamine-systemhook-init.log", "Dopamine-app-startup-0.log",
        "Dopamine-app-startup-501.log", "Dopamine-terminal-startup-0.log",
        "Dopamine-terminal-startup-501.log",
    };
    return kind < RH_DIAGNOSTIC_LOG_COUNT ? names[kind] : NULL;
}

static inline int rh_diagnostic_log_open(const char *root, uint64_t kind, int *out)
{
    if (!out) return EINVAL;
    *out = -1;
    const char *name = rh_diagnostic_log_name(kind);
    if (!name) return EINVAL;
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/var/mobile/Library/Logs/CrashReporter/%s",
                     root ? root : "", name);
    if (n < 0 || (size_t)n >= sizeof(path)) return ENAMETOOLONG;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno;
    struct stat st;
    int result = fstat(fd, &st) == 0 ? 0 : errno;
    if (!result && (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
                    (st.st_uid != 0 && st.st_uid != 501))) result = EACCES;
    if (result) { close(fd); return result; }
    *out = fd;
    return 0;
}

#endif
