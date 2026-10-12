#include "credentials.h"
#include "credential_refs.h"
#include "kernel.h"
#include "primitives.h"
#include "translation.h"
#include "util.h"
#include "roothide_stage.h"
#include "roothider/common.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t *, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *, uid_t);
static pthread_mutex_t credentialLock = PTHREAD_MUTEX_INITIALIZER;

static int credential_read(uint64_t cred, struct rh_credential *c)
{
    if (!cred || !c) return EINVAL;
    memset(c, 0, sizeof(*c));
    uint32_t *fields[] = { &c->uid, &c->ruid, &c->svuid, &c->gid, &c->rgid, &c->svgid };
    uint32_t offsets[] = { koffsetof(ucred, uid), koffsetof(ucred, ruid), koffsetof(ucred, svuid),
                           koffsetof(ucred, groups), koffsetof(ucred, rgid), koffsetof(ucred, svgid) };
    for (unsigned i = 0; i < 6; i++) {
        if (kreadbuf(cred + offsets[i], fields[i], sizeof(uint32_t))) return EIO;
    }
    // cr_ngroups is immediately before the aligned cr_groups array in XNU 10002.
    if (kreadbuf(cred + koffsetof(ucred, groups) - 4, &c->ngroups, sizeof(c->ngroups))) return EIO;
    if (c->ngroups == 0 || c->ngroups > RH_CREDENTIAL_GROUPS) return EINVAL;
    if (kreadbuf(cred + koffsetof(ucred, groups), c->groups, c->ngroups * sizeof(uint32_t))) return EIO;
    return rh_credential_valid(c) ? 0 : EINVAL;
}

int proc_credential_read(uint64_t proc, struct rh_credential *out)
{
    return proc ? credential_read(proc_ucred(proc), out) : EINVAL;
}

static int credential_ref(uint64_t cred, bool strong, bool retain)
{
    uint64_t addr;
    size_t size;
    if (strong) {
        addr = cred + koffsetof(ucred, ref);
        size = sizeof(uint64_t);
    }
    else {
        uint64_t rw = kread_ptr(cred + koffsetof(ucred, rw));
        if (!rw || kread_ptr(rw + 8) != cred) return EINVAL;
        addr = rw + koffsetof(ucred_rw, weak_ref);
        size = sizeof(uint32_t);
    }
    // kaccess_mapped uses the full physrw mapping and cannot be used by a
    // physrw_pte process. Use the active physical accessor, without nesting it.
    uint64_t pa = kvtophys(addr);
    if (!pa) return EIO;
    __block bool changed = false;
    int r = physaccess_mapped(pa, size, ^(void *ptr) {
        changed = strong ? rh_credential_ref64(ptr, retain) : rh_credential_ref32(ptr, retain);
    });
    return r || !changed ? EIO : 0;
}

// Adapted from opa334/Dopamine's proc_copy_ucred / proc_ucred_update_content
// (util.c at 939a3a21400f0dc6d6163b2b5999ba2ace0d2732). The donor is waiting
// at its single-threaded checkpoint; the target is in its RPC/check-in or self.
// Neither may perform set*id concurrently. Both keep a live thread reference.
static int credential_install(uint64_t proc, uint64_t donor, const struct rh_credential *identity)
{
    if (!gSystemInfo.kernelStruct.proc_ro.exists || !gSystemInfo.kernelStruct.ucred_rw.exists ||
        !koffsetof(proc_ro, task_tokens)) return ENOTSUP;
    uint64_t original = proc_ucred(proc), next = proc_ucred(donor);
    if (!original || !next) return ESRCH;
    struct rh_credential actual;
    int r = credential_read(next, &actual);
    if (r || !rh_credential_equal(identity, &actual)) return r ?: EACCES;
    if (original == next) return 0;

    uint64_t procRO = kread_ptr(proc + koffsetof(proc, proc_ro));
    if (!procRO) return EIO;
    uint64_t tokensAddr = procRO + koffsetof(proc_ro, task_tokens);
    uint32_t savedIDs[2], tokens[10], updated[10];
    if (kreadbuf(proc + koffsetof(proc, svuid), &savedIDs[0], sizeof(uint32_t)) ||
        kreadbuf(proc + koffsetof(proc, svgid), &savedIDs[1], sizeof(uint32_t)) ||
        kreadbuf(tokensAddr, tokens, sizeof(tokens))) return EIO;
    memcpy(updated, tokens, sizeof(updated));
    // security_token_t then audit_token_t. Preserve auid/pid/asid/pidversion.
    updated[0] = identity->uid;
    updated[1] = identity->gid;
    unsigned audit = koffsetof(task_token_ro_data, audit_token) / sizeof(uint32_t);
    if (audit != 2) return ENOTSUP;
    updated[audit + 1] = identity->uid;
    updated[audit + 2] = identity->gid;
    updated[audit + 3] = identity->ruid;
    updated[audit + 4] = identity->rgid;

    bool newWeak = false, newStrong = false, oldStrong = false, oldWeak = false;
    int rollbackError = 0;
    // Prepare metadata while the target is waiting. Any failed preparation is
    // restored before returning; the hashed credential contents are immutable.
    r = kwrite32(proc + koffsetof(proc, svuid), identity->svuid);
    if (!r) r = kwrite32(proc + koffsetof(proc, svgid), identity->svgid);
    if (!r) r = kwritebuf(tokensAddr, updated, sizeof(updated));
    if (r) goto rollback;
    if (proc_ucred(proc) != original) { r = EBUSY; goto rollback; }
    r = credential_ref(next, false, true);
    if (r) goto rollback;
    newWeak = true;
    r = credential_ref(next, true, true);
    if (r) goto rollback;
    newStrong = true;
    r = credential_ref(original, true, false);
    if (r) goto rollback;
    oldStrong = true;
    r = credential_ref(original, false, false);
    if (r) goto rollback;
    oldWeak = true;
    r = kwrite64(procRO + koffsetof(proc_ro, ucred), next);
    // A write can report an error after publishing; do not undo references to
    // a credential already installed. The donor stays alive until this returns.
    if (!r || proc_ucred(proc) == next) return 0;

rollback:
    // Original still owns the process pointer on these failure paths.
    if (oldWeak) rollbackError |= credential_ref(original, false, true);
    if (oldStrong) rollbackError |= credential_ref(original, true, true);
    if (newStrong) rollbackError |= credential_ref(next, true, false);
    if (newWeak) rollbackError |= credential_ref(next, false, false);
    rollbackError |= kwrite32(proc + koffsetof(proc, svuid), savedIDs[0]);
    rollbackError |= kwrite32(proc + koffsetof(proc, svgid), savedIDs[1]);
    rollbackError |= kwritebuf(tokensAddr, tokens, sizeof(tokens));
    if (rollbackError) roothide_stage_log("credential.rollback.failed proc=%llx", proc);
    return r < 0 ? EIO : (r ? r : rollbackError);
}

static int64_t credential_milliseconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int credential_ready_read(int fd)
{
    struct rh_credential_ready ready;
    size_t offset = 0;
    int64_t start = credential_milliseconds();
    if (start < 0) return EIO;
    while (offset < sizeof(ready)) {
        int64_t now = credential_milliseconds();
        int64_t remaining = start + 5000 - now;
        if (now < 0) return EIO;
        if (remaining <= 0) return ETIMEDOUT;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, (int)remaining);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return errno;
        if (!r) return ETIMEDOUT;
        ssize_t n = read(fd, (char *)&ready + offset, sizeof(ready) - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return n ? errno : EPIPE;
        offset += (size_t)n;
    }
    return ready.magic == RH_CREDENTIAL_READY_MAGIC && ready.error >= 0 ? ready.error : EPROTO;
}

static void credential_reap(pid_t pid, int version)
{
    if (pid <= 1) return;
    // No unbounded wait inside launchd. Closing the release pipe lets a healthy
    // helper exit; SIGKILL also handles a helper stuck before its checkpoint.
    if (version > 0 && proc_get_pidversion(pid) == version) kill(pid, SIGKILL);
    int64_t start = credential_milliseconds();
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        int status;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid || (r < 0 && errno == ECHILD)) return;
        if (r < 0 && errno != EINTR) break;
        int64_t now = credential_milliseconds();
        if (start < 0 || now < 0 || now - start >= 1000) break;
        struct timespec delay = { .tv_nsec = 10000000 };
        nanosleep(&delay, NULL);
    }
    roothide_stage_log("credential.helper.reap_pending pid=%d", pid);
}

static int credential_pipe(int fds[2])
{
    int original[2];
    if (pipe(original)) return errno;
    // Keep all source descriptors away from helper fd 3/4. No dup2 source can
    // be overwritten by another file action. Parent ends are close-on-exec.
    int a = fcntl(original[0], F_DUPFD_CLOEXEC, 10);
    int b = a >= 0 ? fcntl(original[1], F_DUPFD_CLOEXEC, 10) : -1;
    int error = b < 0 ? errno : 0;
    close(original[0]); close(original[1]);
    if (error) { if (a >= 0) close(a); return error; }
    fds[0] = a; fds[1] = b;
    return 0;
}

int proc_credential_set(uint64_t proc, const char *executable, const struct rh_credential *identity)
{
    if (!proc || !executable || !*executable || !rh_credential_valid(identity)) return EINVAL;
    if (!gSystemInfo.kernelStruct.proc_ro.exists || !gSystemInfo.kernelStruct.ucred_rw.exists) return ENOTSUP;
    pthread_mutex_lock(&credentialLock);
    struct rh_credential current;
    int r = proc_credential_read(proc, &current);
    if (r || rh_credential_equal(&current, identity)) goto unlock;

    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t actions;
    bool attrReady = false, actionsReady = false;
    pid_t pid = 0;
    int donorVersion = 0;
    r = credential_pipe(ready);
    if (r) goto done;
    r = credential_pipe(release);
    if (r) goto done;
    r = posix_spawnattr_init(&attr);
    if (r) goto done;
    attrReady = true;
    r = posix_spawnattr_set_persona_np(&attr, 99, 1);
    if (!r) r = posix_spawnattr_set_persona_uid_np(&attr, 0);
    if (!r) r = posix_spawnattr_set_persona_gid_np(&attr, 0);
    if (!r) r = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    if (r) goto done;
    r = posix_spawn_file_actions_init(&actions);
    if (r) goto done;
    actionsReady = true;
    r = posix_spawn_file_actions_adddup2(&actions, ready[1], 3);
    if (!r) r = posix_spawn_file_actions_adddup2(&actions, release[0], 4);
    for (unsigned i = 0; !r && i < 2; i++) {
        r = posix_spawn_file_actions_addclose(&actions, ready[i]);
        if (!r) r = posix_spawn_file_actions_addclose(&actions, release[i]);
    }
    if (r) goto done;

    char numbers[7 + RH_CREDENTIAL_GROUPS][11];
    uint32_t fields[] = {identity->uid, identity->ruid, identity->svuid,
                         identity->gid, identity->rgid, identity->svgid, identity->ngroups};
    char *argv[10 + RH_CREDENTIAL_GROUPS] = {(char *)executable, RH_CREDENTIAL_HELPER_ARG};
    for (unsigned i = 0; i < 7 + identity->ngroups; i++) {
        snprintf(numbers[i], sizeof(numbers[i]), "%u", i < 7 ? fields[i] : identity->groups[i - 7]);
        argv[2 + i] = numbers[i];
    }
    // Bootstrap privilege/cleanup runs in the application itself. Always use
    // its main entry: launchd may have been injected before the new dyld exists,
    // or the on-disk dyld may still belong to the previous installed version.
    char *env[] = {RH_CREDENTIAL_HELPER_ENV "=1", "_SafeMode=1", "DYLD_IN_CACHE=0",
                   proc == proc_self() ? RH_CREDENTIAL_MAIN_ONLY_ENV "=1" : NULL, NULL};
    r = posix_spawn(&pid, executable, &actions, &attr, argv, env);
    if (r) goto done;
    donorVersion = proc_get_pidversion(pid);
    uint64_t donor = proc_find(pid);
    if (!donor || donorVersion <= 0) { r = ESRCH; goto done; }
    // The early dyld helper has no opportunity to perform normal check-in.
    // Prepare its syscall mask while all of its threads are still suspended.
    proc_allow_all_syscalls(donor);
    if (proc_get_pidversion(pid) != donorVersion || kill(pid, SIGCONT)) { r = EIO; goto done; }
    close(ready[1]); ready[1] = -1;
    close(release[0]); release[0] = -1;
    r = credential_ready_read(ready[0]);
    if (r) goto done;
    if (proc_get_pidversion(pid) != donorVersion || proc_find(pid) != donor) { r = ESRCH; goto done; }
    r = credential_install(proc, donor, identity);

done:
    if (actionsReady) posix_spawn_file_actions_destroy(&actions);
    if (attrReady) posix_spawnattr_destroy(&attr);
    for (unsigned i = 0; i < 2; i++) {
        if (ready[i] >= 0) close(ready[i]);
        if (release[i] >= 0) close(release[i]);
    }
    credential_reap(pid, donorVersion);
    roothide_stage_log("credential.set.end proc=%llx uid=%u gid=%u result=%d", proc, identity->uid, identity->gid, r);
unlock:
    pthread_mutex_unlock(&credentialLock);
    return r;
}
