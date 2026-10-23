#include "userspace_reboot.h"
#include "util.h"
#include "roothide_stage.h"
#include <errno.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int rh_userspace_reboot_prepare(struct rh_userspace_reboot *request, const char *jbctl, char *const env[])
{
    if (!request || !jbctl || !*jbctl) return EINVAL;
    if (request->pid > 0 || request->releaseFD >= 0) return EBUSY;
    if (geteuid() != 0 || getegid() != 0) return EPERM;

    int fds[2];
    int result = cmd_create_handoff_pipe(fds);
    if (result) return result;
    posix_spawn_file_actions_t actions;
    result = posix_spawn_file_actions_init(&actions);
    if (!result) {
        result = posix_spawn_file_actions_adddup2(&actions, fds[0], 3);
        if (!result) result = posix_spawn_file_actions_addclose(&actions, fds[0]);
        if (!result) result = posix_spawn_file_actions_addclose(&actions, fds[1]);
        char *argv[] = {(char *)jbctl, "reboot_userspace", "--waitfor", "3", NULL};
        pid_t pid = -1;
        // This child is prepared while the bootstrap still owns the root
        // credentials. Match the RC7 handoff: start jbctl directly and let
        // fd 3 hold it until the app has restored its credentials. The
        // RootHide spawn wrapper is reserved for ordinary post-bootstrap
        // launches, where child patching is required.
        if (!result) {
            roothide_stage_log("userspace_reboot.spawn.begin path=%s", jbctl);
            result = posix_spawn(&pid, jbctl, &actions, NULL, argv, env);
            roothide_stage_log("userspace_reboot.spawn.end result=%d pid=%d", result, pid);
        }
        if (!result) *request = (struct rh_userspace_reboot){ .pid = pid, .releaseFD = fds[1] };
        posix_spawn_file_actions_destroy(&actions);
    }
    close(fds[0]);
    if (result) close(fds[1]);
    roothide_stage_log("userspace_reboot.prepare result=%d pid=%d", result, request->pid);
    return result;
}

static int reboot_reap(pid_t pid)
{
    // A child may be stuck before main/check-in. Never block App cleanup
    // indefinitely after closing its gate. Its pending action remains cancelled.
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return errno;
    for (;;) {
        int status = 0;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            roothide_stage_log("userspace_reboot.child pid=%d raw_status=%d", pid, status);
            return WIFEXITED(status) ? WEXITSTATUS(status) : EIO;
        }
        if (waited < 0 && errno != EINTR) return errno;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return errno;
        long long elapsed = (now.tv_sec - start.tv_sec) * 1000LL + (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= 5000) return ETIMEDOUT;
        struct timespec pause = { .tv_nsec = 10000000 };
        nanosleep(&pause, NULL);
    }
}

int rh_userspace_reboot_cancel(struct rh_userspace_reboot *request)
{
    if (!request) return EINVAL;
    struct rh_userspace_reboot child = *request;
    *request = RH_USERSPACE_REBOOT_EMPTY;
    // EOF cancels jbctl's --waitfor. No root RPC or signal is needed.
    if (child.releaseFD >= 0) close(child.releaseFD);
    return child.pid > 0 ? reboot_reap(child.pid) : 0;
}

int rh_userspace_reboot_finish(struct rh_userspace_reboot *request)
{
    if (!request || request->pid <= 0 || request->releaseFD < 0) return EINVAL;
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
    roothide_stage_log("userspace_reboot.handoff result=%d pid=%d", result, child.pid);
    int childResult = reboot_reap(child.pid);
    return result ? result : childResult;
}
