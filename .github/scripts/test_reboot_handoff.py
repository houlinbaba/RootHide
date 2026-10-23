#!/usr/bin/env python3
"""Exercise production jbctl handoff cancellation and descriptor ownership.

The deterministic harness runs on Windows/macOS. Apple CI also runs the actual
pipe/spawn/read path. Neither test simulates an iPhone userspace reboot.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for pos in range(opening, len(source)):
        depth += (source[pos] == '{') - (source[pos] == '}')
        if not depth:
            return source[start:pos + 1]
    raise ValueError(signature)


MODEL = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define timespec model_timespec
#define pollfd model_pollfd
#define clock_gettime model_clock
#define poll model_poll
#define read model_read
#define close model_close
#define pipe model_pipe
#define fcntl model_fcntl
#define ssize_t model_ssize_t
typedef long ssize_t;
struct timespec { long tv_sec, tv_nsec; };
struct pollfd { int fd; short events, revents; };
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#define POLLIN 1
#define F_DUPFD_CLOEXEC 100
#define F_SETNOSIGPIPE 101
static int mode, clock_calls, polls, reads, closes, fcntls, fail_fcntl;
static int live[32];
static int clock_gettime(int clock, struct timespec *t) {
    assert(clock == CLOCK_MONOTONIC);
    if (mode == 8) return -1;
    t->tv_sec = clock_calls++; t->tv_nsec = 0; return 0;
}
static int poll(struct pollfd *p, unsigned n, int timeout) {
    assert(n == 1 && p->fd == 10 && p->events == POLLIN);
    assert(timeout > 0 && timeout <= 30000); polls++;
    if (mode == 3) return 0;
    if (mode == 4) { errno = EBADF; return -1; }
    if (mode == 5 || (mode == 6 && polls == 1)) { errno = EINTR; return -1; }
    return 1;
}
static ssize_t read(int fd, void *out, size_t n) {
    assert(fd == 10 && n == 1); reads++;
    if (mode == 1) return 0;
    if (mode == 7 && reads == 1) { errno = EINTR; return -1; }
    if (mode == 9) { errno = EIO; return -1; }
    *(char *)out = mode == 2 ? 'x' : 'w'; return 1;
}
static int close(int fd) { assert(fd >= 0 && fd < 32 && live[fd]); live[fd] = 0; closes++; return 0; }
static int pipe(int fds[2]) { fds[0] = 3; fds[1] = 4; live[3] = live[4] = 1; return 0; }
static int fcntl(int fd, int op, int arg) {
    assert(live[fd]);
    if (++fcntls == fail_fcntl) { errno = EMFILE; return -1; }
    if (op == F_SETNOSIGPIPE) { assert(fd == 11 && arg == 1); return 0; }
    assert(op == F_DUPFD_CLOEXEC && arg == 10 && (fd == 3 || fd == 4));
    int result = fd == 3 ? 10 : 11; live[result] = 1; return result;
}
static void reset(int m) {
    mode = m; clock_calls = polls = reads = closes = fcntls = fail_fcntl = 0;
    memset(live, 0, sizeof(live)); live[10] = 1;
}
'''

CASES = r'''
int main(void) {
    int expected[] = {0, ECANCELED, EPROTO, ETIMEDOUT, EBADF, ETIMEDOUT, 0, 0, EIO, EIO};
    for (int i = 0; i < 10; i++) {
        reset(i); assert(cmd_wait_for_handoff("10") == expected[i]);
        assert(closes == 1 && !live[10] && polls <= 30);
    }
    const char *bad[] = {NULL, "", "-1", "0", "2", "+10", " 10", "10x", "9999999999999999999999"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        reset(0); assert(cmd_wait_for_handoff(bad[i]) == EINVAL);
        assert(!closes && !polls && !reads);
    }
    reset(0); live[10] = 0; int fds[2];
    assert(!cmd_create_handoff_pipe(fds));
    assert(fds[0] == 10 && fds[1] == 11 && !live[3] && !live[4]);
    close(fds[0]); close(fds[1]);
    for (int i = 1; i <= 3; i++) {
        reset(0); live[10] = 0; fail_fcntl = i;
        assert(cmd_create_handoff_pipe(fds) == EMFILE);
        assert(fds[0] == -1 && fds[1] == -1);
        for (unsigned j = 0; j < 32; j++) assert(!live[j]);
    }
    puts("PASS: explicit handoff token, EOF/error cancellation, bounded EINTR, timeout, fd validation and pipe failure cleanup");
    return 0;
}
'''

NATIVE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <spawn.h>
#include <sys/wait.h>
'''

NATIVE_CASES = r'''
int main(int argc, char **argv) {
    if (argc == 2) return cmd_wait_for_handoff(argv[1]);
    for (int scenario = 0; scenario < 3; scenario++) {
        int fds[2]; assert(!cmd_create_handoff_pipe(fds));
        assert(fds[0] >= 10 && fds[1] >= 10);
        assert(fcntl(fds[0], F_GETFD) & FD_CLOEXEC);
        assert(fcntl(fds[1], F_GETFD) & FD_CLOEXEC);
        posix_spawn_file_actions_t actions;
        assert(!posix_spawn_file_actions_init(&actions));
        assert(!posix_spawn_file_actions_adddup2(&actions, fds[0], 3));
        assert(!posix_spawn_file_actions_addclose(&actions, fds[0]));
        assert(!posix_spawn_file_actions_addclose(&actions, fds[1]));
        pid_t pid;
        char *args[] = {argv[0], "3", NULL};
        char *env[] = {NULL};
        assert(!posix_spawn(&pid, argv[0], &actions, NULL, args, env));
        posix_spawn_file_actions_destroy(&actions);
        close(fds[0]);
        if (scenario != 1) {
            char token = scenario == 0 ? 'w' : 'x';
            assert(write(fds[1], &token, 1) == 1);
        }
        close(fds[1]); // EOF must cancel without waiting for the deadline.
        int status;
        assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
        int expected = scenario == 0 ? 0 : scenario == 1 ? ECANCELED : EPROTO;
        assert(WEXITSTATUS(status) == expected);
    }
    puts("PASS: native Darwin pipe/exec cancellation, explicit token and close-on-exec descriptors");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    source = (ROOT / 'BaseBin/libjailbreak/src/util.c').read_text(encoding='utf-8')
    production = function(source, 'int cmd_create_handoff_pipe(') + '\n' + function(source, 'int cmd_wait_for_handoff(')
    app = (ROOT / 'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf-8')
    caller = function(app, '- (int)spawnJbctlAsRootWithArgs:')
    assert 'cmd_create_handoff_pipe(waitPipe)' in caller
    assert 'posix_spawn_file_actions_addclose(&actions, waitPipe[0])' in caller
    assert 'posix_spawn_file_actions_addclose(&actions, waitPipe[1])' in caller
    assert 'posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE)' in caller
    assert 'posix_spawnattr_set_persona_uid_np(&attr, 0)' in caller
    assert 'posix_spawnattr_set_persona_gid_np(&attr, 0)' in caller
    assert 'exec_cmd_roothide_spawn(&pid, argBuf[0], &actions, &attr, argBuf, environ)' in caller
    assert 'spawnResult = posix_spawn(&pid, argBuf[0]' not in caller
    assert caller.index('close(waitPipe[1]); waitPipe[1] = -1') < caller.index('cmd_wait_for_exit(pid)')
    jbctl = (ROOT / 'BaseBin/jbctl/src/main.m').read_text(encoding='utf-8')
    gate = jbctl.index('int r = cmd_wait_for_handoff(argv[argc-1])')
    assert 'return r;' in jbctl[gate:jbctl.index('char *cmd = argv[1]')]
    compiler = [str(args.zig), 'cc'] if args.zig else [shutil.which('clang') or 'clang']
    context = nullcontext(str(args.workdir.resolve())) if args.workdir else tempfile.TemporaryDirectory(prefix='reboot-handoff-')
    with context as directory:
        tmp = Path(directory)
        sanitizers = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
        env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'}
        def run(name, code):
            file = tmp / (name + '.c')
            file.write_text(code, encoding='utf-8')
            binary = tmp / (name + ('.exe' if sys.platform == 'win32' else ''))
            subprocess.run(compiler + sanitizers + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', str(file), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=15, env=env)
        run('handoff-model', MODEL + production + CASES)
        mutant = production.replace('n == 0 ? ECANCELED', 'n == 0 ? 0')
        assert mutant != production
        file = tmp / 'handoff-negative.c'
        file.write_text(MODEL + mutant + CASES, encoding='utf-8')
        binary = tmp / ('handoff-negative.exe' if sys.platform == 'win32' else 'handoff-negative')
        subprocess.run(compiler + sanitizers + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', str(file), '-o', str(binary)], check=True)
        negative = subprocess.run([str(binary)], capture_output=True, timeout=15, env=env)
        assert negative.returncode != 0, 'EOF incorrectly authorized a pending action'
        print('PASS: executing a pending action after EOF is rejected')
        if sys.platform == 'darwin':
            run('handoff-native', NATIVE + production + NATIVE_CASES)
        else:
            if args.zig:
                native = tmp / 'handoff-native.c'
                native.write_text(NATIVE + production + NATIVE_CASES, encoding='utf-8')
                for target in ('aarch64-macos', 'x86_64-macos'):
                    subprocess.run(compiler + ['-target', target, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                             '-c', str(native), '-o', str(tmp / (target + '.o'))], check=True)
                print('PASS: native handoff compiles against Darwin pipe/poll/spawn headers')
            print('LIMIT: native Darwin pipe/spawn test runs in Apple CI; device reboot remains unverified')


if __name__ == '__main__':
    main()
