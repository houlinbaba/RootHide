#include "runtime_diagnostics.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH
#define ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH "/var/mobile/Library/Logs/CrashReporter/Dopamine-systemhook-init.log"
#endif

void roothide_runtime_diagnostic(const char *format, ...)
{
    int savedErrno = errno;
    if (!format) return;

    /* No syslog, XPC, shared mutex, or inherited stderr pipe. A diagnostic
     * failure must not change initialization's result or invoke a fallback
     * service. O_NONBLOCK also prevents opening a substituted FIFO from
     * waiting for a reader; only regular files are accepted below. */
    int fd = open(ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH,
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
                va_list args;
                va_start(args, format);
                int result = vsnprintf(message + prefix, sizeof(message) - prefix - 1,
                                       format, args);
                va_end(args);
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
