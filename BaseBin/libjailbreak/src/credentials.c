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

static int credential_read_bytes(uint64_t address, void *out, size_t size, const char *phase)
{
    int raw = kreadbuf(address, out, size);
    if (raw) rh_failure_note(phase, "kernel_io_return", raw, EIO);
    return raw ? EIO : 0;
}

static int credential_read(uint64_t cred, struct rh_credential *c)
{
    if (!cred || !c) return EINVAL;
    memset(c, 0, sizeof(*c));
    uint32_t *fields[] = { &c->uid, &c->ruid, &c->svuid, &c->gid, &c->rgid, &c->svgid };
    uint32_t offsets[] = { koffsetof(ucred, uid), koffsetof(ucred, ruid), koffsetof(ucred, svuid),
                           koffsetof(ucred, groups), koffsetof(ucred, rgid), koffsetof(ucred, svgid) };
    for (unsigned i = 0; i < 6; i++) {
        if (credential_read_bytes(cred + offsets[i], fields[i], sizeof(uint32_t), "credential_read.field")) return EIO;
    }
    // cr_ngroups is immediately before the aligned cr_groups array in XNU 10002.
    if (credential_read_bytes(cred + koffsetof(ucred, groups) - 4, &c->ngroups, sizeof(c->ngroups), "credential_read.group_count")) return EIO;
    if (c->ngroups == 0 || c->ngroups > RH_CREDENTIAL_GROUPS) return EINVAL;
    if (credential_read_bytes(cred + koffsetof(ucred, groups), c->groups, c->ngroups * sizeof(uint32_t), "credential_read.groups")) return EIO;
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
        if (!rw || kread_ptr(rw + 8) != cred) {
            rh_failure_note("credential_ref.backlink", "credential_status", EINVAL, EINVAL);
            return EINVAL;
        }
        addr = rw + koffsetof(ucred_rw, weak_ref);
        size = sizeof(uint32_t);
    }
    // kaccess_mapped uses the full physrw mapping and cannot be used by a
    // physrw_pte process. Use the active physical accessor, without nesting it.
    uint64_t pa = kvtophys(addr);
    if (!pa) {
        rh_failure_note("credential_ref.translate", "translation_bool", 0, EIO);
        return EIO;
    }
    __block bool changed = false;
    int r = physaccess_mapped(pa, size, ^(void *ptr) {
        changed = strong ? rh_credential_ref64(ptr, retain) : rh_credential_ref32(ptr, retain);
    });
    if (r) rh_failure_note("credential_ref.map", "physaccess_return", r, EIO);
    else if (!changed) rh_failure_note("credential_ref.update", "credential_status", EIO, EIO);
    return r || !changed ? EIO : 0;
}

// Adapted from opa334/Dopamine's proc_copy_ucred / proc_ucred_update_content
// (util.c at 939a3a21400f0dc6d6163b2b5999ba2ace0d2732). The donor is waiting
// at its single-threaded checkpoint; the target is in its RPC/check-in or self.
// Neither may perform set*id concurrently. The source is kept alive by its
// waiting donor or by the counted references owned by a bootstrap snapshot.
static int credential_install_ucred(uint64_t proc, uint64_t next, const struct rh_credential *identity)
{
    if (!gSystemInfo.kernelStruct.proc_ro.exists || !gSystemInfo.kernelStruct.ucred_rw.exists ||
        !koffsetof(proc_ro, task_tokens)) return ENOTSUP;
    uint64_t original = proc_ucred(proc);
    if (!original || !next) return ESRCH;
    struct rh_credential actual;
    int r = credential_read(next, &actual);
    if (r || !rh_credential_equal(identity, &actual)) return r ?: EACCES;
    if (original == next) return 0;

    uint64_t procRO = kread_ptr(proc + koffsetof(proc, proc_ro));
    if (!procRO) return EIO;
    uint64_t tokensAddr = procRO + koffsetof(proc_ro, task_tokens);
    uint32_t savedIDs[2], tokens[10], updated[10];
    if (credential_read_bytes(proc + koffsetof(proc, svuid), &savedIDs[0], sizeof(uint32_t), "install.read_saved_uid") ||
        credential_read_bytes(proc + koffsetof(proc, svgid), &savedIDs[1], sizeof(uint32_t), "install.read_saved_gid") ||
        credential_read_bytes(tokensAddr, tokens, sizeof(tokens), "install.read_tokens")) return EIO;
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
    const char *failurePhase = "install.write_saved_uid";
    const char *failureDomain = "kernel_io_return";
    // Prepare metadata while the target is waiting. Any failed preparation is
    // restored before returning; the hashed credential contents are immutable.
    r = kwrite32(proc + koffsetof(proc, svuid), identity->svuid);
    if (!r) { failurePhase = "install.write_saved_gid"; r = kwrite32(proc + koffsetof(proc, svgid), identity->svgid); }
    if (!r) { failurePhase = "install.write_tokens"; r = kwritebuf(tokensAddr, updated, sizeof(updated)); }
    if (r) goto rollback;
    failurePhase = "install.target_changed";
    failureDomain = "identity_status";
    if (proc_ucred(proc) != original) { r = EBUSY; goto rollback; }
    failureDomain = "credential_status";
    failurePhase = "install.retain_next_weak";
    r = credential_ref(next, false, true);
    if (r) goto rollback;
    newWeak = true;
    failurePhase = "install.retain_next_strong";
    r = credential_ref(next, true, true);
    if (r) goto rollback;
    newStrong = true;
    failurePhase = "install.release_old_strong";
    r = credential_ref(original, true, false);
    if (r) goto rollback;
    oldStrong = true;
    failurePhase = "install.release_old_weak";
    r = credential_ref(original, false, false);
    if (r) goto rollback;
    oldWeak = true;
    failurePhase = "install.publish_credential";
    failureDomain = "kernel_io_return";
    r = kwrite64(procRO + koffsetof(proc_ro, ucred), next);
    // A write can report an error after publishing; do not undo references to
    // a credential already installed. The donor stays alive until this returns.
    if (!r || proc_ucred(proc) == next) return 0;

rollback:
    // Capture the primary write/reference failure before rollback can fail too.
    rh_failure_note(failurePhase, failureDomain, r, r < 0 ? EIO : r);
    // Original still owns the process pointer on these failure paths.
    if (oldWeak) rollbackError |= credential_ref(original, false, true);
    if (oldStrong) rollbackError |= credential_ref(original, true, true);
    if (newStrong) rollbackError |= credential_ref(next, true, false);
    if (newWeak) rollbackError |= credential_ref(next, false, false);
    rollbackError |= kwrite32(proc + koffsetof(proc, svuid), savedIDs[0]);
    rollbackError |= kwrite32(proc + koffsetof(proc, svgid), savedIDs[1]);
    rollbackError |= kwritebuf(tokensAddr, tokens, sizeof(tokens));
    if (rollbackError) roothide_stage_log("credential.rollback.failed result=%d", rollbackError);
    return r < 0 ? EIO : (r ? r : rollbackError);
}

static int credential_install(uint64_t proc, uint64_t donor, const struct rh_credential *identity)
{
    return credential_install_ucred(proc, proc_ucred(donor), identity);
}

static int credential_snapshot_release(struct rh_credential_snapshot *snapshot)
{
    // Clear each flag only after its counted reference has been released.
    // A partial failure remains owned and can be retried without double free.
    if (snapshot->strongRetained) {
        int r = credential_ref(snapshot->ucred, true, false);
        if (r) return r;
        snapshot->strongRetained = false;
    }
    if (snapshot->weakRetained) {
        int r = credential_ref(snapshot->ucred, false, false);
        if (r) return r;
        snapshot->weakRetained = false;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    return 0;
}

int proc_credential_snapshot_self(struct rh_credential_snapshot *snapshot)
{
    if (!snapshot) return EINVAL;
    if (!gSystemInfo.kernelStruct.proc_ro.exists || !gSystemInfo.kernelStruct.ucred_rw.exists) return ENOTSUP;
    pthread_mutex_lock(&credentialLock);
    int r = 0;
    const char *phase = "read_original";
    if (snapshot->proc || snapshot->ucred || snapshot->weakRetained || snapshot->strongRetained) {
        r = EBUSY;
        goto done;
    }
    uint64_t proc = proc_self(), cred = proc ? proc_ucred(proc) : 0;
    struct rh_credential identity;
    r = cred ? credential_read(cred, &identity) : ESRCH;
    if (r) goto done;
    snapshot->proc = proc;
    snapshot->ucred = cred;
    snapshot->identity = identity;
    phase = "retain_weak";
    r = credential_ref(cred, false, true);
    if (!r) {
        snapshot->weakRetained = true;
        phase = "retain_strong";
        r = credential_ref(cred, true, true);
        if (!r) snapshot->strongRetained = true;
    }
    if (r) {
        // If rollback itself fails, keep the remaining pin in the snapshot so
        // the App's ordinary cleanup can release it before discarding state.
        int releaseError = credential_snapshot_release(snapshot);
        if (releaseError) phase = "release_failed_capture";
    }
done:
    roothide_stage_log("credential.snapshot.end phase=%s weak=%d strong=%d result=%d",
                       phase, snapshot->weakRetained, snapshot->strongRetained, r);
    pthread_mutex_unlock(&credentialLock);
    return r;
}

int proc_credential_restore_self(struct rh_credential_snapshot *snapshot)
{
    struct rh_failure_scope scope;
    // pid=0 identifies this local self operation without another process lookup.
    rh_failure_begin(&scope, "restore_self", 0);
    if (!snapshot) return rh_failure_end(&scope, "validate_snapshot", "credential_status", EINVAL, EINVAL);
    pthread_mutex_lock(&credentialLock);
    const char *phase = "validate_snapshot";
    int r = snapshot->proc && snapshot->ucred && snapshot->proc == proc_self() ? 0 : EINVAL;
    if (!r && proc_ucred(snapshot->proc) != snapshot->ucred) {
        if (!snapshot->weakRetained || !snapshot->strongRetained) r = EINVAL;
        else {
            phase = "install_original";
            r = credential_install_ucred(snapshot->proc, snapshot->ucred, &snapshot->identity);
        }
    }
    if (!r) {
        phase = "release_snapshot";
        r = credential_snapshot_release(snapshot);
    }
    rh_failure_note(phase, "credential_status", r, r);
    roothide_stage_log("credential.restore.end phase=%s weak=%d strong=%d result=%d",
                       phase, snapshot->weakRetained, snapshot->strongRetained, r);
    pthread_mutex_unlock(&credentialLock);
    return rh_failure_end(&scope, phase, "credential_status", r, r);
}

int proc_credential_bootstrap_self(void)
{
    pthread_mutex_lock(&credentialLock);
    const char *phase = "find_launchd";
    uint64_t proc = proc_self(), donor = proc_find(1);
    struct rh_credential root;
    int r = proc && donor ? 0 : ESRCH;
    if (!r) {
        phase = "read_launchd_identity";
        r = proc_credential_read(donor, &root);
    }
    if (!r && (root.uid || root.ruid || root.svuid || root.gid || root.rgid || root.svgid)) r = EACCES;
    if (!r) {
        phase = "install_launchd_credential";
        // launchd remains alive with a stable root identity. Transfer counted
        // references and task metadata; never edit its hashed credential/label.
        r = credential_install(proc, donor, &root);
    }
    roothide_stage_log("credential.bootstrap.end phase=%s result=%d", phase, r);
    pthread_mutex_unlock(&credentialLock);
    return r;
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
    if (start < 0) { rh_failure_note("helper_ready.clock_start", "posix_errno", errno, EIO); return EIO; }
    while (offset < sizeof(ready)) {
        int64_t now = credential_milliseconds();
        int64_t remaining = start + 5000 - now;
        if (now < 0) { rh_failure_note("helper_ready.clock_poll", "posix_errno", errno, EIO); return EIO; }
        if (remaining <= 0) { rh_failure_note("helper_ready.deadline", "timeout_status", ETIMEDOUT, ETIMEDOUT); return ETIMEDOUT; }
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, (int)remaining);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) { rh_failure_note("helper_ready.poll", "posix_errno", errno, errno); return errno; }
        if (!r) { rh_failure_note("helper_ready.poll_timeout", "timeout_status", ETIMEDOUT, ETIMEDOUT); return ETIMEDOUT; }
        ssize_t n = read(fd, (char *)&ready + offset, sizeof(ready) - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            int result = n ? errno : EPIPE;
            rh_failure_note("helper_ready.read", n ? "posix_errno" : "stream_eof", n ? errno : 0, result);
            return result;
        }
        offset += (size_t)n;
    }
    bool validReply = ready.magic == RH_CREDENTIAL_READY_MAGIC && ready.error >= 0;
    int result = validReply ? ready.error : EPROTO;
    rh_failure_note("helper_ready.reply", validReply ? "helper_ready_status" : "protocol_status", result, result);
    return result;
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
    const char *phase = "read_target";
    const char *errorDomain = "credential_status";
    pid_t pid = 0;
    bool mainEntry = proc == proc_self() || is_dopamine_app(executable);
    int r = proc_credential_read(proc, &current);
    if (r || rh_credential_equal(&current, identity)) goto unlock;

    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t actions;
    bool attrReady = false, actionsReady = false;
    int donorVersion = 0;
    phase = "pipe_ready";
    errorDomain = "posix_errno";
    r = credential_pipe(ready);
    if (r) goto done;
    phase = "pipe_release";
    r = credential_pipe(release);
    if (r) goto done;
    phase = "spawnattr_init";
    errorDomain = "posix_status";
    r = posix_spawnattr_init(&attr);
    if (r) goto done;
    attrReady = true;
    // Root callers can inherit root directly. Asking for a persona still
    // requires com.apple.private.persona-mgmt even when the caller is root.
    if (geteuid() != 0) {
        phase = "persona";
        r = posix_spawnattr_set_persona_np(&attr, 99, 1);
        if (!r) { phase = "persona_uid"; r = posix_spawnattr_set_persona_uid_np(&attr, 0); }
        if (!r) { phase = "persona_gid"; r = posix_spawnattr_set_persona_gid_np(&attr, 0); }
        if (r) goto done;
    }
    phase = "spawn_flags";
    r = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    if (r) goto done;
    phase = "file_actions_init";
    r = posix_spawn_file_actions_init(&actions);
    if (r) goto done;
    actionsReady = true;
    phase = "file_actions";
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
    // Dopamine handles this argument before App initialization/check-in in main.
    // Use that entry for runtime App credentials too: forcing a dyld patch here
    // adds an unnecessary dependency on the installed session's dyld image.
    // Other executables still need the early dyld entry to avoid running them.
    char *env[] = {RH_CREDENTIAL_HELPER_ENV "=1", "_SafeMode=1", "DYLD_IN_CACHE=0",
                   mainEntry ? RH_CREDENTIAL_MAIN_ONLY_ENV "=1" : NULL, NULL};
    phase = "spawn";
    r = posix_spawn(&pid, executable, &actions, &attr, argv, env);
    if (r) goto done;
    donorVersion = proc_get_pidversion(pid);
    phase = "find_helper";
    errorDomain = "identity_status";
    uint64_t donor = proc_find(pid);
    if (!donor || donorVersion <= 0) { r = ESRCH; goto done; }
    // The early dyld helper has no opportunity to perform normal check-in.
    // Prepare its syscall mask while all of its threads are still suspended.
    proc_allow_all_syscalls(donor);
    phase = "resume_helper";
    int currentVersion = proc_get_pidversion(pid);
    if (currentVersion != donorVersion) {
        roothide_stage_log("credential.helper.resume pid=%d expected_version=%d actual_version=%d result=%d",
                           pid, donorVersion, currentVersion, ESRCH);
        r = ESRCH;
        goto done;
    }
    if (kill(pid, SIGCONT)) {
        r = errno ?: EIO;
        errorDomain = "posix_errno";
        rh_failure_note("resume_helper", "posix_errno", errno, r);
        roothide_stage_log("credential.helper.resume pid=%d version=%d signal_errno=%d", pid, donorVersion, r);
        goto done;
    }
    close(ready[1]); ready[1] = -1;
    close(release[0]); release[0] = -1;
    phase = "helper_ready";
    errorDomain = "helper_ready_status";
    r = credential_ready_read(ready[0]);
    if (r) goto done;
    phase = "validate_helper_pid";
    errorDomain = "identity_status";
    if (proc_get_pidversion(pid) != donorVersion || proc_find(pid) != donor) { r = ESRCH; goto done; }
    phase = "install_helper_credential";
    errorDomain = "credential_status";
    r = credential_install(proc, donor, identity);

done:
    // Capture before file-action destruction, close and reap affect errno.
    rh_failure_note(phase, errorDomain, r, r);
    if (actionsReady) posix_spawn_file_actions_destroy(&actions);
    if (attrReady) posix_spawnattr_destroy(&attr);
    for (unsigned i = 0; i < 2; i++) {
        if (ready[i] >= 0) close(ready[i]);
        if (release[i] >= 0) close(release[i]);
    }
    credential_reap(pid, donorVersion);
    roothide_stage_log("credential.set.end phase=%s uid=%u gid=%u helper_pid=%d result=%d", phase, identity->uid, identity->gid, pid, r);
unlock:
    rh_failure_note(phase, errorDomain, r, r);
    // launchd's activation trace is closed during normal App RPCs. Preserve
    // the failing donor phase without enabling general server tracing or
    // exporting credential pointers, sandbox grants or executable arguments.
    if (r && proc != proc_self()) {
        roothide_stage_file_log(ROOTHIDE_BOOTSTRAP_STAGE_LOG_PATH,
            "credential.runtime.failed phase=%s entry=%s helper_pid=%d result=%d",
            phase, mainEntry ? "app_main" : "early_dyld", pid, r);
    }
    pthread_mutex_unlock(&credentialLock);
    return r;
}
