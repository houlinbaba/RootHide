#!/usr/bin/env python3
"""Execute production journal and unrestrict with injected POSIX failures.

Tests error handling and standalone logger linkage, not an iOS reboot. The
stage-log harness separately exercises real Darwin filesystem operations.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_launchd_injection import extract

PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "roothide_stage.h"
#undef PATH_MAX
#define PATH_MAX 4096
#define O_WRONLY 1
#define O_CREAT 2
#define O_APPEND 4
#define O_CLOEXEC 8
#define O_NOFOLLOW 16
#define O_NONBLOCK 32
#define F_DUPFD_CLOEXEC 99
#define STDERR_FILENO 2
#undef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#define S_ISREG(mode) ((mode) == 1)
struct journal_stat { unsigned st_mode, st_nlink; };
#define stat journal_stat
#define pthread_mutex_t journal_mutex_t
typedef int journal_mutex_t;
#define PTHREAD_MUTEX_INITIALIZER 0
static int depth;
static int pthread_mutex_lock(pthread_mutex_t *m) { (void)m; assert(depth++ == 0); return 0; }
static int pthread_mutex_unlock(pthread_mutex_t *m) { (void)m; assert(--depth == 0); return 0; }
static const char *journal = "/var/mobile/Containers/Data/Application/01234567-89AB-cdef-0123-456789abcdef/Documents/RootHideReboot.log";
static char environment[PATH_MAX], output[32768];
static int opens, fds, writes, stderr_writes, changes, truncates;
static int open_error, stat_error, chmod_error, chown_error, truncate_error, env_error;
static int inode_mode = 1, inode_links = 1, root = 1, redirected;
static bool opened[128];
static char *mock_getenv(const char *name) {
    assert(!strcmp(name, ROOTHIDE_REBOOT_LOG_ENV)); return environment[0] ? environment : NULL;
}
static int mock_setenv(const char *name, const char *value, int overwrite) {
    assert(depth == 1 && !strcmp(name, ROOTHIDE_REBOOT_LOG_ENV) && overwrite); ++changes;
    if (env_error) { errno = env_error; return -1; } strcpy(environment, value); return 0;
}
static int mock_unsetenv(const char *name) {
    assert(depth == 1 && !strcmp(name, ROOTHIDE_REBOOT_LOG_ENV)); ++changes; environment[0] = 0; return 0;
}
static char *mock_realpath(const char *path, char *resolved) {
    if (redirected == 2) { errno = ENOENT; return NULL; }
    if (redirected) strcpy(resolved, "/private/var/mobile/other/Documents");
    else if (!strncmp(path, "/private/", 9)) strcpy(resolved, path);
    else snprintf(resolved, PATH_MAX, "/private%s", path);
    return resolved;
}
static int mock_open(const char *path, int flags, int mode) {
    assert(depth == 1 && flags == (O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK) && mode == 0600);
    ++opens;
    if (open_error || !strcmp(path, "/denied")) { errno = open_error ? open_error : EACCES; return -1; }
    for (int fd = 10; fd < 128; ++fd) if (!opened[fd]) { opened[fd] = true; ++fds; return fd; }
    assert(false); return -1;
}
static int mock_close(int fd) {
    assert(opened[fd]); opened[fd] = false; --fds; errno = EBADF; return 0;
}
static int mock_fstat(int fd, struct journal_stat *st) {
    assert(opened[fd]); if (stat_error) { errno = stat_error; return -1; }
    st->st_mode = inode_mode; st->st_nlink = inode_links; return 0;
}
static int mock_fchmod(int fd, int mode) {
    assert(opened[fd] && mode == 0600 && inode_mode == 1 && inode_links == 1);
    if (chmod_error) { errno = chmod_error; return -1; } return 0;
}
static int mock_fchown(int fd, int uid, int gid) {
    assert(opened[fd] && uid == 501 && gid == 501 && inode_mode == 1 && inode_links == 1);
    if (chown_error) { errno = chown_error; return -1; } return 0;
}
static int mock_ftruncate(int fd, int size) {
    assert(opened[fd] && !size && inode_mode == 1 && inode_links == 1); ++truncates;
    if (truncate_error) { errno = truncate_error; return -1; } return 0;
}
static int mock_fcntl(int fd, int op, int minimum) {
    assert(opened[fd] && op == F_DUPFD_CLOEXEC && minimum == 10);
    for (int n = minimum; n < 128; ++n) if (!opened[n]) { opened[n] = true; ++fds; return n; }
    return -1;
}
static int mock_dprintf(int fd, const char *format, ...) {
    if (fd == STDERR_FILENO) ++stderr_writes;
    else {
        assert(opened[fd]); ++writes;
        va_list args; va_start(args, format);
        vsnprintf(output + strlen(output), sizeof(output) - strlen(output), format, args); va_end(args);
    }
    errno = EIO; return 0;
}
static int mock_clock(int clock, struct timespec *now) { (void)clock; now->tv_sec = 42; now->tv_nsec = 123000000; return 0; }
static int mock_geteuid(void) { return root ? 0 : 501; }
static int mock_getpid(void) { return 123; }
#define getenv mock_getenv
#define setenv mock_setenv
#define unsetenv mock_unsetenv
#define realpath mock_realpath
#define open mock_open
#define close mock_close
#define fstat mock_fstat
#define fchmod mock_fchmod
#define fchown mock_fchown
#define ftruncate mock_ftruncate
#define fcntl mock_fcntl
#define dprintf mock_dprintf
#define clock_gettime mock_clock
#define geteuid mock_geteuid
#define getpid mock_getpid
'''

CASES = r'''
static void configure_expect(const char *path, int result) {
    errno = EDOM;
    assert(roothide_reboot_log_configure(path) == result && errno == EDOM);
    assert(fds == 0 && depth == 0);
    if (result) assert(!environment[0]);
}
int main(void) {
    roothide_stage_log("disabled"); assert(!writes && !opens && !stderr_writes);
    configure_expect(journal, 0);
    int previous_changes = changes; configure_expect(journal, 0); assert(changes == previous_changes);
    errno = ERANGE; roothide_reboot_log("handoff result=%d", 7);
    assert(errno == ERANGE && fds == 0 && writes == 1);
    assert(strstr(output, "[RootHideStage 42.123 pid=123] handoff result=7\n"));
    roothide_stage_log("inactive-mirror"); assert(writes == 2 && !stderr_writes);
    roothide_stage_file_log("/denied", "denied-source-mirror"); assert(writes == 3);
    roothide_stage_file_log(journal, "single-write"); assert(writes == 4);
    assert(roothide_stage_begin("/denied", true) == EACCES);
    roothide_stage_log("failed-stage-mirror"); assert(writes == 5 && stderr_writes == 1);
    roothide_stage_end();
    assert(strstr(output, "inactive-mirror") && strstr(output, "denied-source-mirror"));
    assert(roothide_stage_begin("/stage", false) == 0 && truncates == 1);
    int retained = roothide_stage_duplicate_fd(); assert(retained >= 10 && fds == 2);
    roothide_stage_end(); roothide_stage_begin_from_fd(retained); roothide_stage_end(); assert(fds == 0);
    char alias[PATH_MAX]; snprintf(alias, sizeof(alias), "/private%s", journal); configure_expect(alias, 0);
    root = 0; configure_expect(journal, 0); root = 1;
    const char *invalid[] = {"", "/tmp/RootHideReboot.log",
        "/var/mobile/Containers/Data/Application/01234567-89AB-cdef-0123-456789abcdeg/Documents/RootHideReboot.log",
        "/var/mobile/Containers/Data/Application/01234567_89AB-cdef-0123-456789abcdef/Documents/RootHideReboot.log",
        "/var/mobile/Containers/Data/Application/01234567-89AB-cdef-0123-456789abcdef/Documents/../RootHideReboot.log",
        "/var/mobile/Containers/Data/Application/01234567-89AB-cdef-0123-456789abcdef/Documents/Other.log"};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
        int previous_opens = opens; configure_expect(invalid[i], EINVAL); assert(opens == previous_opens);
    }
    char too_long[PATH_MAX + 1]; memset(too_long, 'a', PATH_MAX); too_long[PATH_MAX] = 0;
    configure_expect(too_long, EINVAL);
    redirected = 1; configure_expect(journal, EINVAL);
    redirected = 2; configure_expect(journal, ENOENT); redirected = 0;
    open_error = EACCES; configure_expect(journal, EACCES); open_error = 0;
    stat_error = EIO; configure_expect(journal, EIO); stat_error = 0;
    inode_mode = 2; configure_expect(journal, EINVAL); inode_mode = 1;
    inode_links = 2; configure_expect(journal, EINVAL); inode_links = 1;
    chmod_error = EPERM; configure_expect(journal, EPERM); chmod_error = 0;
    chown_error = EPERM; configure_expect(journal, EPERM); chown_error = 0;
    env_error = ENOMEM; configure_expect(journal, ENOMEM); env_error = 0;
    truncate_error = EIO;
    errno = ERANGE; assert(roothide_stage_begin("/stage", false) == EIO && errno == ERANGE);
    roothide_stage_end(); assert(fds == 0); truncate_error = 0;
    configure_expect(journal, 0);
    int previous_writes = writes;
    inode_links = 2; roothide_reboot_log("replaced-hardlink"); inode_links = 1;
    redirected = 1; roothide_reboot_log("replaced-parent"); redirected = 0;
    assert(writes == previous_writes && fds == 0);
    configure_expect(NULL, 0); roothide_reboot_log("disabled-again"); assert(writes == previous_writes);
    puts("PASS: journal path/inode/permission checks, errno, fd cleanup, recovery reuse, inactive/denied-source mirroring");
    return 0;
}
'''

RESUME_PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
typedef int pid_t;
#define SIGCONT 18
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
static void roothide_reboot_log(const char *format, ...) { (void)format; }
static int checks, sleeps, patches, signals, delays, check_error, patch_result, signal_error;
static int proc_paused(pid_t pid, bool *paused) {
    assert(pid == 1); ++checks;
    if (check_error) { errno = check_error; return -1; } *paused = checks > delays; return 0;
}
static int usleep(unsigned interval) { assert(interval == 10000 || interval == 100000); ++sleeps; return 0; }
static int callback(pid_t pid) { assert(pid == 1); ++patches; return patch_result; }
static int kill(pid_t pid, int signal) {
    assert(pid == 1 && signal == SIGCONT); ++signals;
    if (signal_error) { errno = signal_error; return -1; } return 0;
}
'''
RESUME_CASES = r'''
static void reset(void) { checks = sleeps = patches = signals = delays = check_error = patch_result = signal_error = 0; }
int main(void) {
    reset(); assert(unrestrict(1, callback, true) == 0 && patches == 1 && signals == 1);
    reset(); assert(unrestrict(1, callback, false) == 0 && patches == 1 && !signals);
    reset(); patch_result = -7; assert(unrestrict(1, callback, true) == -7 && patches == 1 && !signals);
    reset(); check_error = ESRCH; assert(unrestrict(1, callback, true) == -1 && errno == ESRCH && !patches && !signals);
    reset(); delays = 3; assert(unrestrict(1, callback, true) == 0 && checks == 4 && sleeps == 4 && signals == 1);
    reset(); signal_error = ESRCH; assert(unrestrict(1, callback, true) == -1 && errno == ESRCH && signals == 1);
    reset(); signal_error = EPERM; assert(unrestrict(1, callback, true) == -1 && errno == EPERM && signals == 1);
    puts("PASS: production unrestrict callback/check/delayed pause and SIGCONT failure propagation"); return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    source_dir = ROOT / 'BaseBin/libjailbreak/src'
    logger = (source_dir / 'roothide_stage.c').read_text(encoding='utf-8')
    # Keep every production function. Substitute only system interfaces, with
    # no gSystemInfo declaration: systemhook must link the logger independently.
    logger = re.sub(r'^#include[^\n]*\n', '', logger, flags=re.MULTILINE)
    unrestrict = extract((source_dir / 'roothider/common.m').read_text(encoding='utf-8'), 'int unrestrict(')
    assert 'run: python3 .github/scripts/test_reboot_journal.py' in (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    info = (source_dir / 'info.h').read_text(encoding='utf-8')
    assert '_safe_xpc_dictionary_set_string(xdict, "jailbreakInfo.rebootLogPath", gSystemInfo.rebootLogPath)' in info
    assert '_safe_xpc_dictionary_get_string(xdict, "jailbreakInfo.rebootLogPath", &gSystemInfo.rebootLogPath)' in info
    assert 'rebootLogPath, @ROOTHIDE_JAILBREAKD_STAGE_LOG_PATH' in (ROOT / 'Application/Dopamine/UI/DOUIManager.m').read_text(encoding='utf-8')
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='reboot-journal-')
    with context as directory:
        temp = Path(directory)
        compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['cc']

        def execute(name, code, success=True):
            harness = temp / (name + '.c')
            binary = temp / (name + ('.exe' if sys.platform == 'win32' else ''))
            harness.write_text(code, encoding='utf-8')
            subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(source_dir), str(harness), '-o', str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            if success:
                print(result.stdout.strip(), flush=True)

        execute('journal', PREFIX + logger + CASES)
        execute('resume', RESUME_PREFIX + unrestrict + RESUME_CASES)
        broken = unrestrict.replace('errno = resumeError;\n            return -1;', 'errno = resumeError;\n            return 0;')
        assert broken != unrestrict
        execute('ignored-resume-failure', RESUME_PREFIX + broken + RESUME_CASES, False)
        print('PASS: false success on SIGCONT failure is rejected; iOS reboot remains unverified', flush=True)


if __name__ == '__main__':
    main()
