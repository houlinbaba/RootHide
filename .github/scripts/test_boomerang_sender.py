#!/usr/bin/env python3
"""Exercise the real reboot sender, cancellation ownership and caller guard.

The portable model controls scheduling and failures. Apple CI also runs the
sender with real libdispatch. Neither test performs an iPhone reboot or a
kernel primitive transfer.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from test_dyld_entry_redirect import extract

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'BaseBin/launchdhook/src/boomerang.c'

HEADERS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <setjmp.h>
#ifdef _WIN32
typedef int test_pid_t;
#define pid_t test_pid_t
#define WNOHANG 1
#define SIGKILL 9
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#endif
'''

MODEL = r'''
typedef unsigned mach_port_t;
typedef int kern_return_t;
typedef void *posix_spawnattr_t;
typedef void *xpc_object_t;
typedef uint64_t dispatch_time_t;
typedef void (^dispatch_block_t)(void);
struct object {
    int kind, refs, signals, canceled, drained;
    struct object *queue;
    dispatch_block_t event, cancel;
};
typedef struct object *dispatch_semaphore_t, *dispatch_queue_t, *dispatch_source_t;
#define DISPATCH_QUEUE_SERIAL NULL
#define DISPATCH_SOURCE_TYPE_MACH_RECV 1
#define DISPATCH_TIME_NOW 0
#define DISPATCH_TIME_FOREVER UINT64_MAX
#define NSEC_PER_MSEC 1000000LL
#define NSEC_PER_SEC 1000000000LL
#define MACH_PORT_NULL 0
#define MACH_PORT_VALID(p) ((p) && (p) != (mach_port_t)-1)
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_MSG_TYPE_MAKE_SEND 20
#define KERN_SUCCESS 0
static struct object objects[16], main_queue;
static unsigned object_count, semaphore_count;
static struct object *current_source, *done_semaphore, *stopped_semaphore;
static jmp_buf blocked_wait;
static int failure, mode, forever_waits;
#ifdef _WIN32
void *_NSConcreteStackBlock[32], *_NSConcreteGlobalBlock[32];
void _Block_object_assign(void *out, const void *value, int flags) {
    (void)flags; *(const void **)out = value;
}
void _Block_object_dispose(const void *value, int flags) { (void)value; (void)flags; }
#endif
/* Event callbacks run while the sender frame is live. The cancel callback
 * captures only scalar values/pointers and is copied to outlive that frame.
 * Apple CI separately checks these lifetimes with real Blocks/libdispatch. */
struct block_descriptor { unsigned long reserved, size; };
struct block_layout {
    void *isa; int flags, reserved; void (*invoke)(void *);
    struct block_descriptor *descriptor;
};
static dispatch_block_t copy_cancel(dispatch_block_t block) {
    struct block_layout *layout = (void *)block;
    void *copy = malloc(layout->descriptor->size); assert(copy);
    memcpy(copy, layout, layout->descriptor->size); return (dispatch_block_t)copy;
}
static struct object *new_object(int kind) {
    assert(object_count < 16);
    struct object *o = &objects[object_count++];
    memset(o, 0, sizeof(*o)); o->kind = kind; o->refs = 1; return o;
}
static void dispatch_retain(struct object *o) { assert(o && o->refs > 0); o->refs++; }
static void dispatch_release(struct object *o) { assert(o && o->refs > 0); o->refs--; }
static dispatch_semaphore_t dispatch_semaphore_create(long value) {
    assert(value == 0); semaphore_count++;
    if (failure == (int)semaphore_count) return NULL;
    struct object *o = new_object(1);
    if (semaphore_count == 1) done_semaphore = o; else stopped_semaphore = o;
    return o;
}
static dispatch_queue_t dispatch_queue_create(const char *label, void *attr) {
    (void)label; assert(!attr); return failure == 3 ? NULL : new_object(2);
}
static dispatch_queue_t dispatch_get_main_queue(void) { return &main_queue; }
static dispatch_source_t dispatch_source_create(int type, uintptr_t port, unsigned mask, dispatch_queue_t queue) {
    assert(type == 1 && port == 42 && !mask);
    if (failure == 6) return NULL;
    current_source = new_object(3); current_source->queue = queue;
    dispatch_retain(queue); return current_source;
}
static void dispatch_source_set_event_handler(dispatch_source_t s, dispatch_block_t block) { s->event = block; }
static void dispatch_source_set_cancel_handler(dispatch_source_t s, dispatch_block_t block) { s->cancel = copy_cancel(block); }
static void dispatch_resume(dispatch_source_t s) { assert(s == current_source); }
static long dispatch_semaphore_signal(dispatch_semaphore_t s) { assert(s->refs > 0); s->signals++; return 0; }
static dispatch_time_t dispatch_time(dispatch_time_t now, int64_t delta) { assert(!now && delta > 0); return (dispatch_time_t)delta; }
static void drain_cancel(void) {
    struct object *s = current_source;
    if (!s || s->drained || !s->canceled) return;
    s->drained = 1;
    if (s->cancel) { s->cancel(); free((void *)s->cancel); s->cancel = NULL; }
    dispatch_release(s->queue);
}
static void dispatch_source_cancel(dispatch_source_t s) {
    assert(s == current_source); s->canceled = 1;
    if (mode != 3) drain_cancel();
}
static long dispatch_semaphore_wait(dispatch_semaphore_t s, dispatch_time_t deadline) {
    assert(s && s->refs > 0);
    if (s == done_semaphore && !s->signals && current_source &&
        current_source->queue != &main_queue &&
        (mode == 0 || mode == 3 || (mode == 4 && forever_waits))) {
        current_source->event();
    }
    if (s->signals) { s->signals--; return 0; }
    if (deadline == DISPATCH_TIME_FOREVER) { forever_waits++; longjmp(blocked_wait, 1); }
    if (mode == 4) forever_waits = 1;
    return 1;
}
'''

MOCKS = r'''
#define JBROOT_PATH(p) p
#define JBS_BOOMERANG_DONE 42
static int gBoomerangServer;
static int ports, attributes, kills, waits, spawn_calls, published, child_reaped, child_killed;
static int valid_arguments, valid_environment;
static void log_message(const char *format, ...) { (void)format; }
#define JBLogError log_message
#undef mach_task_self
#define mach_task_self() 1
static int fake_allocate(mach_port_t task, int right, mach_port_t *out) {
    (void)task; (void)right; if (failure == 4) return 5; *out = 42; ports++; return 0;
}
#define mach_port_allocate fake_allocate
static int fake_insert(mach_port_t task, mach_port_t name, mach_port_t right, int type) {
    (void)task; (void)name; (void)right; (void)type; return failure == 5 ? 5 : 0;
}
#define mach_port_insert_right fake_insert
static int fake_destroy(mach_port_t task, mach_port_t port) {
    (void)task; assert(port == 42 && ports == 1); ports--; return 0;
}
#define mach_port_destroy fake_destroy
int fake_deallocate(mach_port_t task, mach_port_t port) { (void)task; (void)port; return 0; }
#define mach_port_deallocate fake_deallocate
static int fake_attr_init(posix_spawnattr_t *attr) {
    if (failure == 7) return EINVAL; *attr = (void *)1; attributes++; return 0;
}
#define posix_spawnattr_init fake_attr_init
static int fake_attr_ports(posix_spawnattr_t *attr, mach_port_t *array, uint32_t count) {
    (void)attr; assert(count == 3 && array[2] == 42); return failure == 8 ? EINVAL : 0;
}
#define posix_spawnattr_set_registered_ports_np fake_attr_ports
static int fake_attr_destroy(posix_spawnattr_t *attr) { (void)attr; attributes--; return 0; }
#define posix_spawnattr_destroy fake_attr_destroy
static void notify_helper(void);
static int fake_spawn(pid_t *pid, const char *path, const void *actions,
                      const posix_spawnattr_t *attr, char *const *argv, char *const *env) {
    (void)actions; (void)attr; spawn_calls++;
    assert(!strcmp(path, "/basebin/boomerang"));
    valid_arguments = argv && argv[0] && !strcmp(argv[0], path) && !argv[1];
    valid_environment = env && !env[0];
    if (failure == 9) return EACCES;
    *pid = 123; notify_helper(); return 0;
}
#define posix_spawn fake_spawn
static pid_t fake_wait(pid_t pid, int *status, int flags) {
    assert(pid == 123 && status && flags == WNOHANG); waits++;
    if (mode == 5 || child_reaped) { errno = ECHILD; return -1; }
    if (mode == 6) { errno = EIO; return -1; }
    if (mode == 4 && waits == 1) { errno = EINTR; notify_helper(); return -1; }
    if (mode == 1 || child_killed) { child_reaped = 1; return pid; }
    return 0;
}
#define waitpid fake_wait
static int fake_kill(pid_t pid, int sig) { assert(pid == 123 && sig == SIGKILL); kills++; child_killed = 1; return 0; }
#define kill fake_kill
static int fake_setenv(const char *key, const char *value, int overwrite) {
    assert(!strcmp(key, "BOOMERANG_PID") && !strcmp(value, "123") && overwrite);
    if (failure == 10) { errno = ENOMEM; return -1; } published++; return 0;
}
#define setenv fake_setenv
'''

MODEL_TAIL = r'''
static void notify_helper(void) {}
static int xpc_pipe_receive(mach_port_t port, xpc_object_t *out) { assert(port == 42); *out = (void *)1; return 0; }
static int jbserver_received_boomerang_xpc_message(int *server, xpc_object_t msg) {
    assert(server == &gBoomerangServer && msg); return JBS_BOOMERANG_DONE;
}
static void xpc_release(xpc_object_t msg) { assert(msg == (void *)1); }
static void reset(int fail, int next_mode) {
    for (unsigned i = 0; i < object_count; i++) if (objects[i].cancel) free((void *)objects[i].cancel);
    memset(objects, 0, sizeof(objects)); memset(&main_queue, 0, sizeof(main_queue)); main_queue.refs = 100;
    object_count = semaphore_count = 0; current_source = done_semaphore = stopped_semaphore = NULL;
    ports = attributes = kills = waits = spawn_calls = published = child_reaped = child_killed = 0;
    valid_arguments = valid_environment = forever_waits = 0; failure = fail; mode = next_mode;
}
static void cleaned(void) {
    assert(!ports && !attributes);
    for (unsigned i = 0; i < object_count; i++) assert(objects[i].refs == 0);
}
static int run_stash(void);
'''

MODEL_CASES = r'''
static int run_stash(void) {
    if (setjmp(blocked_wait)) return -999;
    return boomerang_stashPrimitives();
}
int main(void) {
#ifdef BASELINE_AUDIT
    reset(0, 0); assert(run_stash() == -999);
    puts("PASS: baseline sender cannot service its main-queue RPC while waiting forever");
    reset(0, 1); assert(run_stash() == -999);
    puts("PASS: baseline sender has no completion path when the helper exits before DONE");
#else
    for (int fail = 0; fail <= 10; fail++) {
        reset(fail, 0); int result = run_stash(); cleaned();
        if (!fail) assert(!result && published == 1 && !kills && valid_arguments && valid_environment);
        else assert(result != 0 && result != -999 && !published);
        if (fail == 8) assert(!spawn_calls);
        if (fail == 10) assert(kills == 1);
        assert(!forever_waits);
    }
    reset(0, 1); assert(run_stash() == EIO && !kills && !published); cleaned();
    reset(0, 2); assert(run_stash() == ETIMEDOUT && kills == 1 && waits <= 303 && !published); cleaned();
    reset(0, 3); assert(run_stash() == ETIMEDOUT && ports == 1 && !published);
    // Port and semaphore references survive the sender frame until the last
    // in-flight callback drains. Cancellation must not block this caller.
    assert(done_semaphore->refs == 1 && stopped_semaphore->refs == 1);
    drain_cancel(); cleaned();
    reset(0, 4); assert(!run_stash() && waits == 1 && !kills && published == 1); cleaned();
    reset(0, 5); assert(run_stash() == EIO && !kills && !published); cleaned();
    reset(0, 6); assert(run_stash() == EIO && !kills && !published); cleaned();
    puts("PASS: production sender model covers setup failures, blocked main queue, child death, timeout, EINTR, delayed cancellation and cleanup ownership");
#endif
    return 0;
}
'''

DARWIN = r'''
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <xpc/xpc.h>
#include <spawn.h>
#include <pthread.h>
#include <unistd.h>
static int failure, mode, sem_creates, timeout_polls;
static dispatch_source_t current_source;
static dispatch_semaphore_t test_drained;
static dispatch_semaphore_t fake_sem(long n) {
    sem_creates++; if (failure == sem_creates) return NULL; return dispatch_semaphore_create(n);
}
// Function-like macros let the harness call the real functions as (name)(...).
#define dispatch_semaphore_create(n) fake_sem(n)
static dispatch_queue_t fake_queue(const char *label, dispatch_queue_attr_t attr) {
    if (failure == 3) return NULL; return dispatch_queue_create(label, attr);
}
#define dispatch_queue_create fake_queue
static dispatch_source_t fake_source(dispatch_source_type_t type, uintptr_t port, unsigned long mask, dispatch_queue_t q) {
    (void)type; assert(port == 42 && !mask);
    if (failure == 6) return NULL;
    current_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, q); return current_source;
}
#define dispatch_source_create fake_source
static dispatch_time_t short_time(dispatch_time_t now, int64_t delta) {
    assert(now == DISPATCH_TIME_NOW);
    assert(delta == 100 * NSEC_PER_MSEC || delta == NSEC_PER_SEC);
    // No DONE is ever sent in mode 2. Exercise all 300 production polls
    // with expired deadlines instead of accumulating 300 host timer sleeps.
    // Real timeout scheduling is checked once below; cancellation stays real.
    if (mode == 2 && delta == 100 * NSEC_PER_MSEC) {
        timeout_polls++;
        return DISPATCH_TIME_NOW;
    }
    return dispatch_time(now, delta == NSEC_PER_SEC ? 100 * NSEC_PER_MSEC : 10 * NSEC_PER_MSEC);
}
#define dispatch_time(now, delta) short_time(now, delta)
static void delayed_cancel(dispatch_source_t source, dispatch_block_t handler) {
    dispatch_source_set_cancel_handler(source, ^{
        if (mode == 3) usleep(250000);
        handler(); dispatch_semaphore_signal(test_drained);
    });
}
#define dispatch_source_set_cancel_handler delayed_cancel
'''

DARWIN_TAIL = r'''
static void notify_helper(void) {
    if (mode == 0 || mode == 3 || (mode == 4 && waits == 1)) dispatch_source_merge_data(current_source, 1);
}
static int fake_receive(mach_port_t p, xpc_object_t *out) { assert(p == 42); *out = xpc_dictionary_create(NULL, NULL, 0); return 0; }
#define xpc_pipe_receive fake_receive
static int jbserver_received_boomerang_xpc_message(int *server, xpc_object_t msg) {
    assert(server == &gBoomerangServer && msg); return JBS_BOOMERANG_DONE;
}
'''

DARWIN_CASES = r'''
static void reset(int fail, int next_mode) {
    failure = fail; mode = next_mode; sem_creates = timeout_polls = 0; current_source = NULL;
    ports = attributes = kills = waits = spawn_calls = published = child_reaped = child_killed = 0;
    test_drained = (dispatch_semaphore_create)(0);
}
static void drained(void) {
    // This test semaphore is outside the shortened production clock.
    assert(!dispatch_semaphore_wait(test_drained, (dispatch_time)(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)));
    dispatch_release(test_drained); assert(!ports && !attributes);
}
int main(int argc, char **argv) {
    assert(pthread_main_np());
    assert(argc == 3);
    int fail = atoi(argv[1]), next_mode = atoi(argv[2]);
    assert(fail >= 0 && fail <= 10 && next_mode >= 0 && next_mode <= 4);
    assert(!fail || !next_mode);
    // One scenario per process: each owns its dispatch objects, mutable mock
    // state and watchdog budget, including sanitizer/runtime initialization.
    reset(fail, next_mode);
    if (next_mode == 2) {
        // Keep one genuine blocking libdispatch timeout, independent of the
        // poll-loop clock. A broken wait still hits the process watchdog.
        assert(dispatch_semaphore_wait(test_drained,
            (dispatch_time)(DISPATCH_TIME_NOW, 10 * NSEC_PER_MSEC)) != 0);
        puts("PASS: real libdispatch no-signal timeout before 300 expired-deadline polls");
        fflush(stdout);
    }
    int result = boomerang_stashPrimitives();
    if (fail && fail <= 6) {
        assert(result && !ports && !attributes);
        dispatch_release(test_drained);
    }
    else {
        drained();
        if (fail) assert(result && !published);
        else if (next_mode == 1) assert(result == EIO && !kills);
        else if (next_mode == 2) assert(result == ETIMEDOUT && kills == 1 &&
                                       timeout_polls == 300 && waits == 302 && !published);
        else if (next_mode == 3) assert(result == ETIMEDOUT && !published);
        else assert(!result && published == 1 && !kills);
    }
    printf("PASS: real libdispatch sender failure=%d mode=%d\n", fail, next_mode);
    return 0;
}
'''

WRAPPER_MODEL = r'''
typedef uint64_t dispatch_time_t;
typedef void *dispatch_semaphore_t, *dispatch_source_t;
#define DISPATCH_TIME_NOW 0
#define NSEC_PER_MSEC 1000000LL
#define NSEC_PER_SEC 1000000000LL
static int failure, mode, sem_creates, timeout_polls;
static int ports, attributes, kills, waits, spawn_calls, published, child_reaped, child_killed;
static dispatch_source_t current_source;
static dispatch_semaphore_t test_drained;
static dispatch_semaphore_t dispatch_semaphore_create(long n) { assert(!n); return (void *)1; }
static dispatch_time_t dispatch_time(dispatch_time_t now, int64_t delta) { assert(!now); return delta; }
static long dispatch_semaphore_wait(dispatch_semaphore_t sem, dispatch_time_t deadline) {
    assert(sem && deadline == 2 * NSEC_PER_SEC); return 0;
}
static void dispatch_release(dispatch_semaphore_t sem) { assert(sem); }
'''

WRAPPER_CASES = r'''
int main(void) {
    for (int fail = 0; fail <= 2; fail++) {
        reset(fail, 0);
        assert(test_drained && sem_creates == 0);
        assert((dispatch_semaphore_create(0) != NULL) == (fail != 1));
        assert((dispatch_semaphore_create(0) != NULL) == (fail != 2));
        assert(sem_creates == 2);
        assert(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC) == 10 * NSEC_PER_MSEC);
        assert(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC) == 100 * NSEC_PER_MSEC);
        drained();
        assert(sem_creates == 2);
    }
    reset(0, 2);
    for (int i = 0; i < 300; i++)
        assert(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC) == DISPATCH_TIME_NOW);
    assert(timeout_polls == 300);
    assert(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC) == 100 * NSEC_PER_MSEC);
    drained();
    puts("PASS: Darwin wrappers preserve failure injection, 300 expired polls, real cancellation and the two-second drain deadline");
    return 0;
}
'''

CALLER = r'''
#define LOG_PROCESS_LAUNCHES 0
#define MNT_FORCE 1
struct _posix_spawn_args_desc { int unused; };
static bool gInEarlyBoot;
static int handoff_error, original_calls, unmount_calls;
static char *test_environment[] = {NULL};
#undef environ
#define environ test_environment
static int _NSGetExecutablePath(char *out, unsigned *size) { (void)size; strcpy(out, "/sbin/launchd"); return 0; }
static int boomerang_stashPrimitives(void) { return handoff_error; }
static int unmount(const char *path, int flags) { (void)path; (void)flags; unmount_calls++; return 0; }
static const char *test_getenv(const char *key) { (void)key; return NULL; }
#define getenv test_getenv
static int test_unsetenv(const char *key) { (void)key; return 0; }
#define unsetenv test_unsetenv
static int jbupdate_basebin(const char *path) { (void)path; assert(0); return 1; }
#define abort_with_reason(a,b,c,d) do { (void)(a); (void)(b); (void)(c); (void)(d); assert(0); } while (0)
#define JBLogError(...) ((void)0)
static int __posix_spawn_orig_wrapper(pid_t *pid, const char *path, struct _posix_spawn_args_desc *desc,
                                     char *const *argv, char *const *env) {
    (void)pid; (void)path; (void)desc; (void)argv;
    assert(env == test_environment); original_calls++; return 0;
}
'''

CALLER_CASES = r'''
int main(void) {
    const int failures[] = {EIO, ENOMEM, ETIMEDOUT};
    for (unsigned i = 0; i < sizeof(failures)/sizeof(failures[0]); i++) {
        for (int early = 0; early < 2; early++) {
            original_calls = unmount_calls = 0; handoff_error = failures[i]; gInEarlyBoot = early;
            assert(__posix_spawn_hook(NULL, "/sbin/launchd", NULL, NULL, NULL) == failures[i]);
            assert(gInEarlyBoot == early && !original_calls && !unmount_calls);
        }
    }
    original_calls = unmount_calls = handoff_error = 0; gInEarlyBoot = false;
    assert(!__posix_spawn_hook(NULL, "/sbin/launchd", NULL, NULL, NULL));
    assert(gInEarlyBoot && original_calls == 1 && unmount_calls == 1);
    puts("PASS: production caller preserves early-boot state and does not reboot after a failed handoff");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    parser.add_argument('--baseline-ref')
    args = parser.parse_args()
    source = (ROOT / SOURCE).read_text(encoding='utf-8')
    cleanup = extract(source, 'static void terminateFailedBoomerang(')
    sender = extract(source, 'int boomerang_stashPrimitives(void)')
    helper = (ROOT / 'BaseBin/boomerang/src/main.c').read_text(encoding='utf-8')
    assert helper.index('if (jbclient_initialize_primitives_internal(false) != 0) return -1;') < helper.index('kr = mach_ports_register(launchdTaskPort')
    assert 'if (jbclient_boomerang_done() != 0) return -1;' in helper
    assert 'int boomerang_stashPrimitives(void);' in (ROOT / 'BaseBin/launchdhook/src/boomerang.h').read_text()
    hook = extract((ROOT / 'BaseBin/launchdhook/src/spawn_hook.c').read_text(encoding='utf-8'), 'int __posix_spawn_hook(')
    # Execute the complete reboot branch; unrelated normal-spawn handling is
    # outside this harness. Availability is the only substituted expression.
    stop = hook.index('\n#if LOG_PROCESS_LAUNCHES', hook.index('return __posix_spawn_orig_wrapper'))
    hook = re.sub(r'__builtin_available\(iOS 17\.0, \*\)', '(1)', hook[:stop]) + '\nreturn 1234;\n}\n'
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
    flags = ['-std=gnu11', '-fblocks', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-function', '-Wno-deprecated-declarations']
    if sys.platform == 'darwin':
        flags += ['-fsanitize=address,undefined']
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='boomerang-sender-')
    with context as directory:
        temp = Path(directory)
        c_file = temp / 'sender.c'
        binary = temp / ('sender.exe' if sys.platform == 'win32' else 'sender')

        def run(text, *, execute=True, reject=False, extra_flags=(), cases=None):
            c_file.write_text(text, encoding='utf-8')
            subprocess.run(compiler + flags + list(extra_flags) + [str(c_file), '-o', str(binary)], check=True)
            if execute:
                for case in cases if cases is not None else [()]:
                    if cases is not None:
                        print(f'RUN: real libdispatch sender failure={case[0]} mode={case[1]}', flush=True)
                    try:
                        result = subprocess.run([str(binary), *map(str, case)], capture_output=reject, timeout=15)
                    except subprocess.TimeoutExpired as error:
                        raise RuntimeError(f'sender watchdog expired for case {case}; 15-second per-case deadline') from error
                    if reject:
                        assert result.returncode != 0, 'broken sender escaped the regression'
                    else:
                        result.check_returncode()

        # Execute the actual Darwin wrapper functions/macros and reset/drain
        # helpers on every host. Compilation alone cannot catch macro capture.
        wrappers = '\n'.join([
            extract(DARWIN, 'static dispatch_semaphore_t fake_sem('),
            re.search(r'^#define dispatch_semaphore_create\b[^\n]*', DARWIN, re.M).group(),
            extract(DARWIN, 'static dispatch_time_t short_time('),
            re.search(r'^#define dispatch_time\b[^\n]*', DARWIN, re.M).group(),
        ]) + '\n'
        drain = extract(DARWIN_CASES, 'static void reset(') + '\n' + extract(DARWIN_CASES, 'static void drained(')
        run(HEADERS + WRAPPER_MODEL + wrappers + drain + WRAPPER_CASES)
        for fixed, broken in [
            ('#define dispatch_semaphore_create(n) fake_sem(n)', '#define dispatch_semaphore_create fake_sem'),
            ('#define dispatch_time(now, delta) short_time(now, delta)', '#define dispatch_time short_time'),
        ]:
            mutation = wrappers.replace(fixed, broken)
            assert mutation != wrappers
            run(HEADERS + WRAPPER_MODEL + mutation + drain + WRAPPER_CASES, reject=True)
        print('PASS: wrapper regression rejects both original object-like macro aliases')

        model = HEADERS + MODEL + MOCKS + MODEL_TAIL
        run(model + cleanup + sender + MODEL_CASES)
        if args.zig and sys.platform != 'darwin':
            for target in ['aarch64-macos', 'x86_64-macos']:
                subprocess.run(compiler + ['-target', target] + flags + ['-c', str(c_file), '-o', str(temp / (target + '.o'))], check=True)
            # Compile the unchanged functions with the actual dispatch headers
            # too, including their C ownership APIs and Blocks declarations.
            declarations = HEADERS + '#include <dispatch/dispatch.h>\n#include <mach/mach.h>\n#include <spawn.h>\n#include <xpc/xpc.h>\n'
            declarations += '#define JBROOT_PATH(p) p\n#define JBS_BOOMERANG_DONE 42\nstatic int gBoomerangServer;\n#define JBLogError(...) ((void)0)\n'
            declarations += 'extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t *, uint32_t);\nextern int xpc_pipe_receive(mach_port_t, xpc_object_t *);\nextern int jbserver_received_boomerang_xpc_message(int *, xpc_object_t);\n'
            c_file.write_text(declarations + cleanup + sender, encoding='utf-8')
            for target in ['aarch64-macos', 'x86_64-macos']:
                subprocess.run(compiler + ['-target', target] + flags + ['-c', str(c_file), '-o', str(temp / ('sdk-' + target + '.o'))], check=True)
            print('PASS: production sender compiles with Darwin Mach and dispatch headers')
            c_file.write_text(HEADERS + DARWIN + MOCKS + DARWIN_TAIL + cleanup + sender + DARWIN_CASES, encoding='utf-8')
            for target in ['aarch64-macos', 'x86_64-macos']:
                subprocess.run(compiler + ['-target', target] + flags + ['-c', str(c_file), '-o', str(temp / ('dispatch-' + target + '.o'))], check=True)
            print('PASS: real-libdispatch harness compiles against Darwin headers')

        run(HEADERS + CALLER + hook + CALLER_CASES, extra_flags=['-Wno-unused-parameter'])
        wrong_queue = sender.replace('0, serverQueue)', '0, dispatch_get_main_queue())')
        assert wrong_queue != sender
        run(model + cleanup + wrong_queue + MODEL_CASES, reject=True)
        infinite_cancel = sender.replace('dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)', 'DISPATCH_TIME_FOREVER')
        assert infinite_cancel != sender
        run(model + cleanup + infinite_cancel + MODEL_CASES, reject=True)
        print('PASS: regressions reject a main-queue receive source and an infinite cancellation wait')
        if args.baseline_ref:
            baseline = subprocess.check_output(['git', '-c', f'safe.directory={ROOT.as_posix()}', 'show', f'{args.baseline_ref}:{SOURCE}'], cwd=ROOT, text=True)
            old = extract(baseline, 'void boomerang_stashPrimitives()').replace('void boomerang_stashPrimitives()', 'static void baseline_stash(void)', 1)
            wrapper = '\nstatic int boomerang_stashPrimitives(void) { baseline_stash(); return 0; }\n'
            run('#define BASELINE_AUDIT\n' + model + old + wrapper + MODEL_CASES)
        if sys.platform == 'darwin':
            # The main queue is never drained by this main-thread test. Use
            # genuine dispatch queues, Blocks copying, cancellation and XPC.
            cases = [(fail, 0) for fail in range(11)] + [(0, mode) for mode in range(1, 5)]
            run(HEADERS + DARWIN + MOCKS + DARWIN_TAIL + cleanup + sender + DARWIN_CASES, cases=cases)
        else:
            print('LIMIT: real libdispatch scheduling/lifetimes run in Apple CI; iPhone reboot remains unverified')


if __name__ == '__main__':
    main()
