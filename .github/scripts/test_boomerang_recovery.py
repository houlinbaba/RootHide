#!/usr/bin/env python3
"""Run the production recovery function with failed Mach/RPC operations.

This checks recovery error propagation and nonblocking child cleanup. It does
not emulate reboot, primitive transfer, Mach transport, or launchd scheduling.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

from test_dyld_entry_redirect import extract

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'BaseBin/launchdhook/src/boomerang.c'

PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#ifdef _WIN32
typedef int pid_t;
#define WNOHANG 1
#define WEXITED 4
#else
#include <sys/types.h>
#include <sys/wait.h>
#endif
typedef unsigned mach_port_t, mach_msg_type_number_t;
#define MACH_PORT_NULL 0
#define MACH_PORT_VALID(p) ((p) != 0 && (p) != (mach_port_t)-1)
#define KERN_SUCCESS 0
#define mach_task_self() 1
static mach_port_t ports[3];
static unsigned port_count;
static int lookup_result, register_result, primitive_result, done_result;
static int custom_calls, register_calls, primitive_calls, done_calls, unset_calls;
static mach_port_t custom_port;
static int wait_calls, blocking_waits, wait_interrupts, wait_error, wait_result;
static pid_t waited_pid;
static bool have_kcall, used_pte;
static const char *pid_environment;
static int errors;
void test_log(const char *format, ...) { (void)format; }
#define JBLogError test_log
static int mach_ports_lookup(int task, mach_port_t **out, unsigned *count) {
    assert(task == 1); *out = ports; *count = port_count; return lookup_result;
}
static int mach_ports_register(int task, mach_port_t *out, unsigned count) {
    assert(task == 1 && out == ports && count == 3 && out[2] == MACH_PORT_NULL);
    register_calls++; return register_result;
}
static void jbclient_xpc_set_custom_port(mach_port_t port) {
    custom_port = port; custom_calls++;
}
static bool is_kcall_available(void) { return have_kcall; }
static int jbclient_initialize_primitives_internal(bool pte) {
    assert(custom_calls == 1 && register_calls == 1);
    primitive_calls++; used_pte = pte; return primitive_result;
}
static int jbclient_boomerang_done(void) {
    assert(primitive_calls == 1); done_calls++; return done_result;
}
static const char *test_getenv(const char *key) {
    assert(!strcmp(key, "BOOMERANG_PID")); return pid_environment;
}
#define getenv test_getenv
static int test_unsetenv(const char *key) {
    assert(!strcmp(key, "BOOMERANG_PID")); unset_calls++; return 0;
}
#define unsetenv test_unsetenv
static pid_t test_waitpid(pid_t pid, int *status, int flags) {
    assert(status); wait_calls++; waited_pid = pid;
    if (flags != WNOHANG) blocking_waits++;
    if (wait_interrupts) { wait_interrupts--; errno = EINTR; return -1; }
    if (wait_error) { errno = wait_error; return -1; }
    return wait_result;
}
#define waitpid test_waitpid
'''

CASES = r'''
static void reset(void) {
    ports[0] = ports[1] = 0; ports[2] = 42; port_count = 3;
    lookup_result = register_result = primitive_result = done_result = 0;
    custom_calls = register_calls = primitive_calls = done_calls = unset_calls = 0;
    custom_port = MACH_PORT_NULL;
    wait_calls = blocking_waits = wait_interrupts = wait_error = wait_result = 0;
    waited_pid = 0; have_kcall = used_pte = false; pid_environment = "123";
}
static void expect(bool condition, const char *message) {
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); errors++; }
}
int main(void) {
    reset();
    expect(!boomerang_recoverPrimitives(true, true), "normal recovery succeeds");
    expect(custom_port == 42 && used_pte && done_calls == 1 && unset_calls == 1 &&
           wait_calls == 1 && waited_pid == 123 && !blocking_waits,
           "successful recovery performs one nonblocking wait for the helper");

    reset(); lookup_result = 7;
    expect(boomerang_recoverPrimitives(true, true) == -1 && !custom_calls &&
           !primitive_calls && !done_calls && !wait_calls && !unset_calls,
           "failed lookup has no downstream effects");
    reset(); port_count = 2;
    expect(boomerang_recoverPrimitives(true, true) == -1 && !custom_calls,
           "short registered-port array is rejected");
    for (unsigned i = 0; i < 2; i++) {
        reset(); ports[2] = i ? (mach_port_t)-1 : MACH_PORT_NULL;
        expect(boomerang_recoverPrimitives(true, true) == -2 && !custom_calls,
               "null or dead helper port is rejected");
    }
    reset(); register_result = 7;
    expect(boomerang_recoverPrimitives(true, true) == 7 && !primitive_calls &&
           !done_calls && !wait_calls && !unset_calls,
           "failed registered-port update stops recovery");
    reset(); primitive_result = -5;
    expect(boomerang_recoverPrimitives(true, true) == -5 && !done_calls &&
           !wait_calls && !unset_calls,
           "failed primitive recovery preserves identity and never sends DONE");
    reset(); done_result = -6;
    expect(boomerang_recoverPrimitives(false, true) == -6 && done_calls == 1 &&
           !wait_calls && !unset_calls,
           "failed DONE preserves identity and never waits for helper exit");
    reset();
    expect(!boomerang_recoverPrimitives(false, false) && !used_pte &&
           !done_calls && !wait_calls && !unset_calls,
           "recovery without helper shutdown preserves its identity");
    reset(); have_kcall = true;
    expect(!boomerang_recoverPrimitives(true, true) && !used_pte,
           "first recovery keeps the existing kcall selection");
    reset();
    expect(!boomerang_recoverPrimitives(false, true) && !used_pte,
           "later recovery keeps the existing full-physrw selection");

    const char *invalid_pids[] = {NULL, "", "0", "1", "-1", "-123", "123x",
        "2147483648", "999999999999999999999999", "+123", " 123", "123 "};
    for (unsigned i = 0; i < sizeof(invalid_pids) / sizeof(invalid_pids[0]); i++) {
        reset(); pid_environment = invalid_pids[i];
        expect(!boomerang_recoverPrimitives(false, true) && !wait_calls &&
               unset_calls == (pid_environment != NULL),
               "invalid helper PID never selects a process group or another child");
    }
    reset(); wait_interrupts = 2;
    expect(!boomerang_recoverPrimitives(false, true) && wait_calls == 3 &&
           !blocking_waits && waited_pid == 123,
           "interrupted nonblocking reaps are retried for the same child");
    reset(); wait_error = ECHILD;
    expect(!boomerang_recoverPrimitives(false, true) && wait_calls == 1 && !blocking_waits,
           "already reaped helper does not fail a completed recovery");
    reset(); wait_result = 123;
    expect(!boomerang_recoverPrimitives(false, true) && wait_calls == 1 && !blocking_waits,
           "exited helper is reaped once");
    reset(); wait_error = EIO;
    expect(!boomerang_recoverPrimitives(false, true) && wait_calls == 1 && !blocking_waits,
           "cleanup failure does not undo a completed handoff");
    if (errors) return 1;
    puts("PASS: recovery errors propagate; failed recovery preserves helper identity; cleanup never blocks or selects a process group");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    parser.add_argument('--baseline-ref', help='Also verify that this Git revision fails the regression')
    args = parser.parse_args()
    production = extract((ROOT / SOURCE).read_text(encoding='utf-8'),
                         'int boomerang_recoverPrimitives(')
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['cc']
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror']
    if sys.platform == 'darwin':
        flags += ['-fsanitize=address,undefined']
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='boomerang-recovery-')
    with context as directory:
        temp = Path(directory)
        harness = temp / 'boomerang_recovery.c'
        binary = temp / ('boomerang_recovery.exe' if sys.platform == 'win32' else 'boomerang_recovery')

        def build(function):
            harness.write_text(PREFIX + function + CASES, encoding='utf-8')
            subprocess.run(compiler + flags + [str(harness), '-o', str(binary)], check=True)

        build(production)
        subprocess.run([str(binary)], check=True, timeout=10)
        if args.zig and sys.platform != 'darwin':
            for target in ['aarch64-macos', 'x86_64-macos']:
                subprocess.run(compiler + ['-target', target] + flags +
                               ['-c', str(harness), '-o', str(temp / (target + '.o'))], check=True)
            print('PASS: recovery harness compiles against Darwin headers')

        def reject(function, label):
            build(function)
            result = subprocess.run([str(binary)], capture_output=True, timeout=10)
            assert result.returncode != 0, label + ' escaped the regression'
            print('PASS: regression rejects ' + label)
            return result.stderr.decode(errors='replace')

        false_success = production.replace('if (result != 0) return result;',
                                           'if (result != 0) return 0;')
        assert false_success != production
        reject(false_success, 'false recovery success')
        blocking_wait = production.replace('waitpid(boomerangPid, &boomerangStatus, WNOHANG)',
                                            'waitpid(boomerangPid, &boomerangStatus, 0)')
        assert blocking_wait != production
        reject(blocking_wait, 'blocking helper cleanup')
        if args.baseline_ref:
            baseline = subprocess.check_output(['git', '-c', f'safe.directory={ROOT.as_posix()}',
                                                'show', f'{args.baseline_ref}:{SOURCE}'], cwd=ROOT, text=True)
            failures = reject(extract(baseline, 'int boomerang_recoverPrimitives('),
                              'the unchanged ' + args.baseline_ref + ' recovery function')
            for message in ['failed primitive recovery preserves identity and never sends DONE',
                            'failed DONE preserves identity and never waits for helper exit',
                            'successful recovery performs one nonblocking wait for the helper']:
                assert 'FAIL: ' + message in failures, 'baseline did not reproduce: ' + message
            print('PASS: baseline reproduces ignored recovery/DONE errors and blocking cleanup')


if __name__ == '__main__':
    main()
