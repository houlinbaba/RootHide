#include "roothide_stage.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t gStageLock = PTHREAD_MUTEX_INITIALIZER;
static int gStageFD = -1;
static bool gStageActive = false;

static int stage_open_private(const char *path, bool append)
{
    // NONBLOCK prevents a substituted FIFO from hanging launchd; check the
    // inode before truncation or ownership changes, including hard links.
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    struct stat st = {0};
    if (fstat(fd, &st) != 0) goto failed;
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1) {
        errno = EINVAL;
        goto failed;
    }
    if (geteuid() == 0 && fchown(fd, 501, 501) != 0) goto failed;
    if (fchmod(fd, 0600) != 0) goto failed;
    if (!append && ftruncate(fd, 0) != 0) goto failed;
    return fd;
failed:;
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

static int reboot_log_path_check(const char *path)
{
    if (!path || strlen(path) >= PATH_MAX) return EINVAL;
    const char *normalized = path;
    if (!strncmp(normalized, "/private/", 9)) normalized += 8;
    const char *prefix = "/var/mobile/Containers/Data/Application/";
    size_t prefixLength = strlen(prefix);
    if (strncmp(normalized, prefix, prefixLength)) return EINVAL;
    const char *identifier = normalized + prefixLength;
    if (strlen(identifier) != 36 + strlen("/Documents/" ROOTHIDE_REBOOT_LOG_NAME)) return EINVAL;
    for (unsigned i = 0; i < 36; i++) {
        char c = identifier[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return EINVAL;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return EINVAL;
        }
    }
    if (strcmp(identifier + 36, "/Documents/" ROOTHIDE_REBOOT_LOG_NAME)) return EINVAL;
    // Reject symlinked intermediate directories as well as the final inode.
    char parent[PATH_MAX], resolved[PATH_MAX];
    size_t parentLength = strlen(path) - strlen("/" ROOTHIDE_REBOOT_LOG_NAME);
    memcpy(parent, path, parentLength);
    parent[parentLength] = 0;
    if (!realpath(parent, resolved)) return errno;
    const char *resolvedNormalized = resolved;
    if (!strncmp(resolvedNormalized, "/private/", 9)) resolvedNormalized += 8;
    return strlen(resolvedNormalized) == strlen(normalized) - strlen("/" ROOTHIDE_REBOOT_LOG_NAME) &&
           !strncmp(resolvedNormalized, normalized, strlen(resolvedNormalized)) ? 0 : EINVAL;
}

int roothide_reboot_log_configure(const char *path)
{
    int savedErrno = errno;
    int result = 0;
    pthread_mutex_lock(&gStageLock);
    if (path) {
        result = reboot_log_path_check(path);
        if (result == 0) {
            int fd = stage_open_private(path, true);
            if (fd < 0) result = errno;
            else {
                close(fd);
                const char *previous = getenv(ROOTHIDE_REBOOT_LOG_ENV);
                if ((!previous || strcmp(previous, path)) &&
                    setenv(ROOTHIDE_REBOOT_LOG_ENV, path, 1) != 0) result = errno;
            }
        }
    }
    // Do not keep writing a previous activation's journal after setup fails.
    // Avoid changing environ when primitive recovery reuses the same path.
    if (!path || result != 0) {
        if (unsetenv(ROOTHIDE_REBOOT_LOG_ENV) != 0 && result == 0) result = errno;
    }
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
    return result;
}

static void stage_write_event(int fd, const char *message)
{
    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME, &now);
    dprintf(fd, "[RootHideStage %lld.%03ld pid=%d] %s\n",
            (long long)now.tv_sec, now.tv_nsec / 1000000, getpid(), message);
}

static void reboot_log_write(const char *message, const char *originalPath)
{
    const char *path = getenv(ROOTHIDE_REBOOT_LOG_ENV);
    if (reboot_log_path_check(path) != 0 || (originalPath && !strcmp(path, originalPath))) return;
    int fd = stage_open_private(path, true);
    if (fd >= 0) {
        stage_write_event(fd, message);
        close(fd);
    }
}

void roothide_reboot_log(const char *format, ...)
{
    int savedErrno = errno;
    char message[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    pthread_mutex_lock(&gStageLock);
    reboot_log_write(message, NULL);
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
}

void roothide_stage_file_log(const char *path, const char *format, ...)
{
    int savedErrno = errno;
    char message[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    pthread_mutex_lock(&gStageLock);
    int fd = stage_open_private(path, true);
    if (fd >= 0) {
        stage_write_event(fd, message);
        close(fd);
    }
    reboot_log_write(message, path);
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
}

int roothide_stage_begin(const char *path, bool append)
{
    int savedErrno = errno;
    pthread_mutex_lock(&gStageLock);
    if (gStageFD >= 0) close(gStageFD);
    // No stdio buffering, no child inheritance, and no following a symlink.
    // The mobile App must be able to read/append after temporary root ends.
    // Keep the file private, and transfer root-created logs to mobile.
    gStageFD = stage_open_private(path, append);
    int result = gStageFD < 0 ? errno : 0;
    gStageActive = true; // Keep stderr diagnostics even if file creation fails.
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
    return result;
}

int roothide_stage_duplicate_fd(void)
{
    int savedErrno = errno;
    pthread_mutex_lock(&gStageLock);
    int fd = gStageFD >= 0 ? fcntl(gStageFD, F_DUPFD_CLOEXEC, 10) : -1;
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
    return fd;
}

void roothide_stage_begin_from_fd(int fd)
{
    int savedErrno = errno;
    pthread_mutex_lock(&gStageLock);
    if (gStageFD >= 0 && gStageFD != fd) close(gStageFD);
    gStageFD = fd;
    gStageActive = true;
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
}

void roothide_stage_log(const char *format, ...)
{
    int savedErrno = errno;
    char message[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    pthread_mutex_lock(&gStageLock);
    if (gStageActive) {
        if (gStageFD >= 0) {
            stage_write_event(gStageFD, message);
        }
        stage_write_event(STDERR_FILENO, message);
    }
    reboot_log_write(message, NULL);
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
}

void roothide_stage_end(void)
{
    int savedErrno = errno;
    pthread_mutex_lock(&gStageLock);
    if (gStageFD >= 0) close(gStageFD);
    gStageFD = -1;
    gStageActive = false;
    pthread_mutex_unlock(&gStageLock);
    errno = savedErrno;
}
