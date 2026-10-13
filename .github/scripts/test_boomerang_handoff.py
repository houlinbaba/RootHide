#!/usr/bin/env python3
"""Run production reboot handoff with fake Mach/spawn and real Darwin dispatch.

Windows validates ARC syntax and executes recovery error propagation. Device
reboot and kernel primitive mapping still require a real iPhone test.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_launchd_injection import extract, SYNTAX_PREFIX

DARWIN_MOCKS = r'''
#define JBROOT_PATH(p) p
#define JBS_BOOMERANG_DONE 42
static int gBoomerangServer;
static int failure, ports, destroys, attributes, kills, waits, replies, mode;
static dispatch_source_t currentSource;
static int fake_allocate(mach_port_t task, int right, mach_port_t *port) {
    (void)task; (void)right;
    if (failure == 1) return KERN_FAILURE;
    *port = 42; ++ports; return KERN_SUCCESS;
}
#define mach_port_allocate fake_allocate
static int fake_insert(mach_port_t task, mach_port_t name, mach_port_t right, int type) {
    (void)task; (void)name; (void)right; (void)type;
    return failure == 2 ? KERN_FAILURE : KERN_SUCCESS;
}
#define mach_port_insert_right fake_insert
static int fake_destroy(mach_port_t task, mach_port_t port) {
    (void)task; assert(port == 42 && ports == 1); --ports; ++destroys;
    return KERN_SUCCESS;
}
#define mach_port_destroy fake_destroy
static dispatch_source_t fake_source(dispatch_source_type_t type, uintptr_t port,
                                     unsigned long mask, dispatch_queue_t queue) {
    (void)type; (void)mask; assert(port == 42 && queue != dispatch_get_main_queue());
    if (failure == 3) return NULL;
    currentSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, queue);
    return currentSource;
}
#define dispatch_source_create fake_source
static dispatch_time_t short_time(dispatch_time_t when, int64_t delta) {
    assert(delta == 100 * NSEC_PER_MSEC);
    return dispatch_time(when, NSEC_PER_MSEC);
}
#define dispatch_time short_time
static int fake_attr_init(posix_spawnattr_t *attr) {
    (void)attr; if (failure == 4) return EINVAL; ++attributes; return 0;
}
#define posix_spawnattr_init fake_attr_init
static int fake_ports(posix_spawnattr_t *attr, mach_port_t *portsArray, uint32_t count) {
    (void)attr; assert(count == 3 && portsArray[2] == 42);
    return failure == 5 ? EINVAL : 0;
}
#define posix_spawnattr_set_registered_ports_np fake_ports
static int fake_attr_destroy(posix_spawnattr_t *attr) { (void)attr; --attributes; return 0; }
#define posix_spawnattr_destroy fake_attr_destroy
static int fake_spawn(pid_t *pid, const char *path, const void *actions,
                      const posix_spawnattr_t *attr, char *const *argv, char *const *env) {
    (void)actions; (void)attr;
    assert(!strcmp(path, "/basebin/boomerang") && !strcmp(argv[0], path) && !argv[1]);
    assert(env && !env[0]);
    if (failure == 6) return EACCES;
    *pid = 123;
    if (mode == 0) dispatch_source_merge_data(currentSource, 1);
    return 0;
}
#define posix_spawn fake_spawn
static int fake_receive(mach_port_t port, xpc_object_t *dict) {
    assert(port == 42); *dict = xpc_dictionary_create(NULL, NULL, 0); return 0;
}
#define xpc_pipe_receive fake_receive
static int jbserver_received_boomerang_xpc_message(int *server, xpc_object_t dict) {
    assert(server == &gBoomerangServer && dict); ++replies; return JBS_BOOMERANG_DONE;
}
static pid_t fake_wait(pid_t pid, int *status, int flags) {
    assert(pid == 123 && flags == WNOHANG); if (status) *status = 0; ++waits;
    if (mode == 1) return pid;
    if (mode == 2 && waits == 1) { errno = EINTR; return -1; }
    return 0;
}
#define waitpid fake_wait
static int fake_kill(pid_t pid, int sig) { assert(pid == 123 && sig == SIGKILL); ++kills; return 0; }
#define kill fake_kill
static int fake_setenv(const char *name, const char *value, int replace) {
    assert(!strcmp(name, "BOOMERANG_PID") && !strcmp(value, "123") && replace);
    if (failure == 7) { errno = ENOMEM; return -1; } return 0;
}
#define setenv fake_setenv
'''

DARWIN_CASES = r'''
int main(void) {
    // This is the main thread, and the main queue is never drained during
    // stashPrimitives. A main-queue receive source cannot complete this case.
    assert(pthread_main_np());
    for (failure = 0; failure <= 7; failure++) {
        ports = destroys = attributes = kills = waits = replies = mode = 0;
        int result = boomerang_stashPrimitives();
        assert(ports == 0 && attributes == 0);
        if (failure == 0) assert(!result && replies == 1 && !kills);
        else assert(result != 0);
        if (failure >= 2) assert(destroys == 1);
        if (failure == 7) assert(kills == 1);
    }
    failure = 0; mode = 1; kills = waits = 0;
    assert(boomerang_stashPrimitives() == EIO && !kills && waits == 1 && !ports);
    mode = 2; kills = waits = 0;
    assert(boomerang_stashPrimitives() == ETIMEDOUT && kills == 1 && waits > 1 && !ports);
    puts("PASS: production handoff completes with main queue blocked, observes child death/timeout, and drains cancellation before port destruction");
    return 0;
}
'''

RECOVERY_PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
typedef int pid_t;
typedef unsigned mach_port_t, mach_msg_type_number_t;
#define MACH_PORT_NULL 0
#define WNOHANG 1
#define mach_task_self() 1
static mach_port_t ports[3] = {0, 0, 42};
static int primitive_result, done_result, done_calls, wait_calls;
static int mach_ports_lookup(int task, mach_port_t **out, unsigned *count) {
    (void)task; *out = ports; *count = 3; return 0;
}
static int mach_ports_register(int task, mach_port_t *out, unsigned count) {
    (void)task; (void)out; (void)count; return 0;
}
static void jbclient_xpc_set_custom_port(mach_port_t port) { assert(port == 42); }
static char *fake_getenv(const char *key) { (void)key; return "123"; }
#define getenv fake_getenv
static int fake_unsetenv(const char *key) { (void)key; return 0; }
#define unsetenv fake_unsetenv
static bool is_kcall_available(void) { return false; }
static int jbclient_initialize_primitives_internal(bool pte) { (void)pte; return primitive_result; }
static int jbclient_boomerang_done(void) { ++done_calls; return done_result; }
static pid_t waitpid(pid_t pid, int *status, int flags) {
    (void)status; assert(pid == 123 && flags == WNOHANG); ++wait_calls; return 0;
}
'''

RECOVERY_CASES = r'''
int main(void) {
    ports[2] = 42; primitive_result = -5;
    assert(boomerang_recoverPrimitives(true, true) == -5 && !done_calls && !wait_calls);
    ports[2] = 42; primitive_result = 0; done_result = -6;
    assert(boomerang_recoverPrimitives(false, true) == -6 && done_calls == 1 && !wait_calls);
    ports[2] = 42; done_result = 0;
    assert(!boomerang_recoverPrimitives(false, true) && wait_calls == 1);
    ports[2] = 42;
    assert(!boomerang_recoverPrimitives(false, false) && wait_calls == 1);
    puts("PASS: recovery failure never sends DONE; failed DONE propagates; helper exit never blocks launchd");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    source = (ROOT / 'BaseBin/launchdhook/src/boomerang.c').read_text(encoding='utf-8')
    stash = extract(source, 'int boomerang_stashPrimitives()')
    recover = extract(source, 'int boomerang_recoverPrimitives(')
    helper = (ROOT / 'BaseBin/boomerang/src/main.c').read_text(encoding='utf-8')
    assert helper.index('if (jbclient_initialize_primitives_internal(false) != 0)') < helper.index('kr = mach_ports_register(launchdTaskPort')
    assert 'if (jbclient_boomerang_done() != 0) return -1;' in helper
    hook = (ROOT / 'BaseBin/launchdhook/src/spawn_hook.c').read_text(encoding='utf-8')
    assert 'gInEarlyBoot = wasInEarlyBoot;' in hook and 'return handoffResult;' in hook
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='boomerang-')
    with context as directory:
        temp = Path(directory)
        compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
        harness = temp / 'recovery.c'
        harness.write_text(RECOVERY_PREFIX + recover + RECOVERY_CASES, encoding='utf-8')
        binary = temp / ('recovery.exe' if sys.platform == 'win32' else 'recovery')
        subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror', str(harness), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        if sys.platform == 'darwin':
            harness = temp / 'stash.c'
            harness.write_text('#include <stdbool.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <dispatch/dispatch.h>\n#include <mach/mach.h>\n#include <xpc/xpc.h>\n#include <spawn.h>\n#include <sys/wait.h>\n#include <signal.h>\n#include <errno.h>\n#include <assert.h>\n#include <pthread.h>\n' + DARWIN_MOCKS + stash + DARWIN_CASES, encoding='utf-8')
            binary = temp / 'stash'
            subprocess.run(['xcrun', 'clang', '-fblocks', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', str(harness), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=30)
        elif args.zig:
            prefix = SYNTAX_PREFIX.replace('extern int gBoomerangServer;', '')
            prefix += '''
#define ENOMEM 12
#define EIO 5
#define ETIMEDOUT 60
#define WNOHANG 1
#define SIGKILL 9
#define NSEC_PER_MSEC 1000000
static int gBoomerangServer;
typedef _Bool bool;
#define false 0
extern void xpc_release(xpc_object_t);
extern int kill(pid_t, int);
extern int snprintf(char *, unsigned long, const char *, ...);
extern int setenv(const char *, const char *, int);
'''
            harness = temp / 'stash.m'
            harness.write_text(prefix + stash, encoding='utf-8')
            subprocess.run([str(args.zig.resolve()), 'clang', '-cc1', '-triple', 'arm64-apple-ios17.0.0', '-x', 'objective-c', '-fobjc-arc', '-fblocks', '-Wall', '-Wextra', '-Werror', '-fsyntax-only', str(harness)], check=True)
            print('PASS: production stash ARC syntax; real dispatch regression runs in Apple CI')


if __name__ == '__main__':
    main()
