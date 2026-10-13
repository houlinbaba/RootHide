#include "userspace_reboot.h"
#include "roothide_stage.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int rh_userspace_reboot_prepare(struct rh_userspace_reboot *request, const char *jbctl, char *const env[])
{
    if (!request || !jbctl || !*jbctl) return EINVAL;
    if (request->pid > 0 || request->releaseFD >= 0) return EBUSY;
    if (geteuid() != 0 || getegid() != 0) return EPERM;
    int pipeFD[2];
    if (pipe(pipeFD)) return errno;
    // Keep sources away from fd 3, and prevent writer inheritance from keeping
    // the child alive when the App crashes or cancels before handoff.
    int reader = fcntl(pipeFD[0], F_DUPFD_CLOEXEC, 10);
    int writer = reader >= 0 ? fcntl(pipeFD[1], F_DUPFD_CLOEXEC, 10) : -1;
    int result = writer < 0 ? errno : 0;
    close(pipeFD[0]); close(pipeFD[1]);
    if (result) {
        if (reader >= 0) close(reader);
        return result;
    }
    // Darwin pipes support per-descriptor SIGPIPE suppression. A child which
    // dies/times out must produce an error, never terminate the UIKit process.
    if (fcntl(writer, F_SETNOSIGPIPE, 1) < 0) {
        result = errno;
        close(reader); close(writer);
        return result;
    }
    posix_spawn_file_actions_t actions;
    result = posix_spawn_file_actions_init(&actions);
    if (!result) {
        result = posix_spawn_file_actions_adddup2(&actions, reader, 3);
        if (!result) result = posix_spawn_file_actions_addclose(&actions, reader);
        if (!result) result = posix_spawn_file_actions_addclose(&actions, writer);
        char *argv[] = {(char *)jbctl, "reboot_userspace", "--waitfor", "3", NULL};
        pid_t pid = -1;
        if (!result) result = posix_spawn(&pid, jbctl, &actions, NULL, argv, env);
        if (!result) *request = (struct rh_userspace_reboot){ .pid = pid, .releaseFD = writer };
        posix_spawn_file_actions_destroy(&actions);
    }
    close(reader);
    if (result) close(writer);
    roothide_stage_log("userspace_reboot.prepare result=%d pid=%d uid=%u euid=%u", result,
                       request->pid, (unsigned)getuid(), (unsigned)geteuid());
    return result;
}

static int reboot_reap(pid_t pid)
{
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0) return errno;
    roothide_stage_log("userspace_reboot.child pid=%d raw_status=%d", pid, status);
    return WIFEXITED(status) ? WEXITSTATUS(status) : EIO;
}

int rh_userspace_reboot_finish(struct rh_userspace_reboot *request)
{
    if (!request || request->pid <= 0 || request->releaseFD < 0) return EINVAL;
    // Initial activation must have returned to the mobile App.
    // Keep the gate closed if callers accidentally skip credential restoration.
    if (getuid() != 501 || geteuid() != 501 || getgid() != 501 || getegid() != 501) {
        rh_userspace_reboot_cancel(request);
        return EPERM;
    }
    struct rh_userspace_reboot child = *request;
    *request = RH_USERSPACE_REBOOT_EMPTY;
    char token = 'w';
    ssize_t count;
    do { count = write(child.releaseFD, &token, 1); } while (count < 0 && errno == EINTR);
    int result = count == 1 ? 0 : (count < 0 ? errno : EIO);
    close(child.releaseFD);
    roothide_stage_log("userspace_reboot.handoff result=%d pid=%d uid=%u euid=%u", result,
                       child.pid, (unsigned)getuid(), (unsigned)geteuid());
    int childResult = reboot_reap(child.pid);
    return result ?: childResult;
}

int rh_userspace_reboot_cancel(struct rh_userspace_reboot *request)
{
    if (!request) return EINVAL;
    struct rh_userspace_reboot child = *request;
    *request = RH_USERSPACE_REBOOT_EMPTY;
    if (child.releaseFD >= 0) close(child.releaseFD);
    // EOF makes the child exit; no signal or temporary root is required.
    return child.pid > 0 ? reboot_reap(child.pid) : 0;
}

int rh_userspace_reboot_wait(int fd)
{
    if (fd < 0) return EINVAL;
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return errno;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return errno;
        long long elapsed = (now.tv_sec - start.tv_sec) * 1000LL + (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= 60000) return ETIMEDOUT;
        struct pollfd item = { .fd = fd, .events = POLLIN };
        int result = poll(&item, 1, (int)(60000 - elapsed));
        if (result < 0) { if (errno == EINTR) continue; return errno; }
        if (!result) return ETIMEDOUT;
        if (item.revents & POLLNVAL) return EBADF;
        char token = 0;
        ssize_t count = read(fd, &token, 1);
        if (count < 0) { if (errno == EINTR) continue; return errno; }
        return count == 1 && token == 'w' ? 0 : ECANCELED;
    }
}
