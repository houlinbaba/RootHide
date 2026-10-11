#include "runtime_diagnostics.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH
#define ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH "/var/mobile/Library/Logs/CrashReporter/Dopamine-systemhook-init.log"
#endif

#ifndef ROOTHIDE_APP_STARTUP_DIAGNOSTIC_PREFIX
#define ROOTHIDE_APP_STARTUP_DIAGNOSTIC_PREFIX "/var/mobile/Library/Logs/CrashReporter/Dopamine-app-startup"
#endif

static void roothide_runtime_vdiagnostic(const char *path, const char *format, va_list args)
{
    int savedErrno = errno;
    if (!format) return;

    /* No syslog, XPC, shared mutex, or inherited stderr pipe. A diagnostic
     * failure must not change initialization's result or invoke a fallback
     * service. O_NONBLOCK also prevents opening a substituted FIFO from
     * waiting for a reader; only regular files are accepted below. */
    int fd = open(path,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                  0644);
    if (fd >= 0) {
        struct stat info;
        if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
            info.st_nlink == 1 && info.st_uid == geteuid()) {
            struct timespec now = {0};
            clock_gettime(CLOCK_MONOTONIC, &now);
            char message[2048];
            int prefix = snprintf(message, sizeof(message),
                                  "[RootHideRuntime %lld.%03ld pid=%d] ",
                                  (long long)now.tv_sec, now.tv_nsec / 1000000,
                                  getpid());
            if (prefix > 0 && (size_t)prefix < sizeof(message) - 2) {
                int result = vsnprintf(message + prefix, sizeof(message) - prefix - 1,
                                       format, args);
                if (result >= 0) {
                    size_t length = strlen(message);
                    message[length++] = '\n';
                    /* Best effort, one write. Regular-file I/O is not a hard
                     * deadline, but it has no dependency on service startup. */
                    (void)write(fd, message, length);
                }
            }
        }
        close(fd);
    }
    errno = savedErrno;
}

void roothide_runtime_diagnostic(const char *format, ...)
{
    if (!format) return;
    va_list args;
    va_start(args, format);
    roothide_runtime_vdiagnostic(ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH, format, args);
    va_end(args);
}

static void roothide_runtime_diagnostic_at_path(const char *path, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static void roothide_runtime_diagnostic_at_path(const char *path, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    roothide_runtime_vdiagnostic(path, format, args);
    va_end(args);
}

void roothide_app_startup_diagnostic(const char *process, const char *event, int result)
{
    int savedErrno = errno;
    if (!process || !event || (strcmp(process, "Sileo") && strcmp(process, "RootHide"))) return;
    uid_t uid = geteuid();
    if (uid != 0 && uid != 501) return;
    // RootHide can change uid during initialization. Separate files preserve
    // the writer's ownership check without trusting another user's log file.
    char path[512];
    int count = snprintf(path, sizeof(path), "%s-%u.log", ROOTHIDE_APP_STARTUP_DIAGNOSTIC_PREFIX, (unsigned)uid);
    if (count >= 0 && (size_t)count < sizeof(path)) {
        roothide_runtime_diagnostic_at_path(path, "app=%s event=%s result=%d", process, event, result);
    }
    errno = savedErrno;
}
