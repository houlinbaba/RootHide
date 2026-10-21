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
#if ROOTHIDE_TERMINAL_DIAGNOSTICS
#include <stdatomic.h>
#endif

#ifndef ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH
#define ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH "/var/mobile/Library/Logs/CrashReporter/Dopamine-systemhook-init.log"
#endif

#ifndef ROOTHIDE_APP_STARTUP_DIAGNOSTIC_PREFIX
#define ROOTHIDE_APP_STARTUP_DIAGNOSTIC_PREFIX "/var/mobile/Library/Logs/CrashReporter/Dopamine-app-startup"
#endif

static void roothide_runtime_vdiagnostic(const char *path, off_t limit, const char *format, va_list args)
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
            info.st_nlink == 1 && info.st_uid == geteuid() &&
            (!limit || (info.st_size >= 0 && info.st_size < limit))) {
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
    roothide_runtime_vdiagnostic(ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH, 0, format, args);
    va_end(args);
}

static void roothide_runtime_diagnostic_at_path(const char *path, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static void roothide_runtime_diagnostic_at_path(const char *path, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    roothide_runtime_vdiagnostic(path, 0, format, args);
    va_end(args);
}

void roothide_app_startup_diagnostic(const char *process, const char *event, int result)
{
    RH_TERMINAL_DIAGNOSTIC(process, event, NULL, result, 0, 0);
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

#if ROOTHIDE_TERMINAL_DIAGNOSTICS
#ifndef ROOTHIDE_TERMINAL_DIAGNOSTIC_PREFIX
#define ROOTHIDE_TERMINAL_DIAGNOSTIC_PREFIX "/var/mobile/Library/Logs/CrashReporter/Dopamine-terminal-startup"
#endif

// Only fixed process basenames are logged, never arguments, environment,
// working directories or arbitrary command paths.
static const char *terminal_name(const char *path)
{
    if (!path) return NULL;
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (name[0] == '-') name++;
    static const char *const names[] = {"NewTerm", "NewTerm2", "Terminal",
        "NewTermLoginHelper", "login", "zsh", "bash", "dash", "sh"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (!strcmp(name, names[i])) return names[i];
    return NULL;
}

static void terminal_write(const char *path, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static void terminal_write(const char *path, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    roothide_runtime_vdiagnostic(path, 256 * 1024, format, args);
    va_end(args);
}

void roothide_terminal_diagnostic(const char *process, const char *event,
    const char *target, int result, int child, int error)
{
    int savedErrno = errno;
    const char *name = terminal_name(process);
    uid_t uid = geteuid();
    if (!name || !event || (uid != 0 && uid != 501)) { errno = savedErrno; return; }
    static _Atomic unsigned count;
    // Saturate rather than wrapping: no more than 96 events per process image.
    unsigned current = atomic_load_explicit(&count, memory_order_relaxed);
    while (current < 96 && !atomic_compare_exchange_weak_explicit(&count, &current,
        current + 1, memory_order_relaxed, memory_order_relaxed)) {}
    if (current >= 96) { errno = savedErrno; return; }
    char path[512];
    int length = snprintf(path, sizeof(path), "%s-%u.log", ROOTHIDE_TERMINAL_DIAGNOSTIC_PREFIX, (unsigned)uid);
    if (length > 0 && (size_t)length < sizeof(path)) {
        const char *targetName = terminal_name(target);
        terminal_write(path, "terminal=%s event=%s target=%s result=%d child=%d errno=%d uid=%u euid=%u ppid=%d",
            name, event, targetName ?: "other-or-none", result, child, error,
            (unsigned)getuid(), (unsigned)uid, getppid());
    }
    errno = savedErrno;
}
#endif
