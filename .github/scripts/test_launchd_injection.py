#!/usr/bin/env python3
"""Exercise extracted injection control flow with fake Mach/spawn and real dispatch.

Darwin runs the production Objective-C method with Foundation/ARC and a data
source replacing Mach readiness. Windows checks Objective-C syntax using Zig
and runs the extracted wait helper. Neither mode validates launchd injection.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def extract(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for pos in range(opening, len(source)):
        depth += (source[pos] == '{') - (source[pos] == '}')
        if not depth:
            return source[start:pos + 1]
    raise ValueError(signature)


MOCKS = r'''
#define JBROOT_PATH(path) path
#define jbinfo(field) "/test/.jbroot"
#define JBErrorCodeFailedLaunchdInjection -11
static NSString *const JBErrorDomain = @"test";
static int gBoomerangServer;
#define JBS_BOOMERANG_DONE 9
static int fail_allocate, fail_insert, fail_attr, fail_register, fail_spawn;
static int fail_wait, interrupt_wait, child_status, injector_error, source_failure;
static int receive_error, reply_result, event_mode, mobile;
static int ports, destroys, attrs, spawn_calls, wait_calls, inject_calls, replies;
static dispatch_source_t current_source;
static dispatch_semaphore_t handler_entered;
static int active_handler;
static unsigned test_uid(void) { return mobile ? 501 : 0; }
#define getuid test_uid
#define geteuid test_uid
#define getgid test_uid
#define getegid test_uid
static void roothide_stage_log(const char *fmt, ...) { (void)fmt; }
static void logSpawnImageDiagnostics(const char *path) { (void)path; }
static int fake_allocate(mach_port_t task, int right, mach_port_t *port) {
    (void)task; (void)right;
    if (fail_allocate) return fail_allocate;
    ++ports; *port = 42; return 0;
}
#define mach_port_allocate fake_allocate
static int fake_insert(mach_port_t task, mach_port_t name, mach_port_t right, int type) {
    (void)task; (void)name; (void)right; (void)type; return fail_insert;
}
#define mach_port_insert_right fake_insert
static int fake_destroy(mach_port_t task, mach_port_t port) {
    (void)task; assert(port == 42 && ports == 1 && !active_handler);
    --ports; ++destroys; return 0;
}
#define mach_port_destroy fake_destroy
static dispatch_source_t fake_source_create(dispatch_source_type_t type, uintptr_t handle,
                                           unsigned long mask, dispatch_queue_t queue) {
    (void)type; assert(handle == 42); (void)mask;
    if (source_failure) return nil;
    current_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, queue);
    return current_source;
}
#define dispatch_source_create fake_source_create
static dispatch_time_t short_deadline(dispatch_time_t when, int64_t delta) {
    assert(delta == 30 * NSEC_PER_SEC);
    return dispatch_time(when, 200 * 1000 * 1000);
}
#define dispatch_time short_deadline
static int fake_attr_init(posix_spawnattr_t *attr) {
    if (fail_attr) return fail_attr;
    *attr = (posix_spawnattr_t)0; ++attrs; return 0;
}
#define posix_spawnattr_init fake_attr_init
static int fake_register(posix_spawnattr_t *attr, mach_port_t *array, unsigned count) {
    (void)attr; assert(count == 3 && array[2] == 42); return fail_register;
}
#define posix_spawnattr_set_registered_ports_np fake_register
static int fake_attr_destroy(posix_spawnattr_t *attr) { (void)attr; --attrs; return 0; }
#define posix_spawnattr_destroy fake_attr_destroy
static int fake_spawn(pid_t *pid, const char *path, const void *actions,
                      const posix_spawnattr_t *attr, char *const *argv, char *const *env) {
    (void)actions; (void)attr; assert(!env && !strcmp(path, "/basebin/jbctl"));
    assert(!strcmp(argv[1], "internal") && !strcmp(argv[2], "launchd_stash_port"));
    ++spawn_calls; if (fail_spawn) return fail_spawn;
    *pid = 123; return 0;
}
#define posix_spawn fake_spawn
static pid_t fake_wait(pid_t pid, int *status, int options) {
    assert(pid == 123 && options == 0); ++wait_calls;
    if (interrupt_wait) { --interrupt_wait; errno = EINTR; return -1; }
    if (fail_wait) { errno = fail_wait; return -1; }
    *status = child_status; return pid;
}
#define waitpid fake_wait
static int xpc_pipe_receive(mach_port_t port, xpc_object_t *dict) {
    assert(port == 42);
    *dict = receive_error ? nil : xpc_dictionary_create(NULL, NULL, 0);
    return receive_error;
}
static int jbserver_received_boomerang_xpc_message(int *server, xpc_object_t dict) {
    assert(server == &gBoomerangServer && dict); ++replies;
    if (event_mode == 2) {
        active_handler = 1;
        dispatch_semaphore_signal(handler_entered);
        struct timespec delay = {.tv_nsec = 10000000}; nanosleep(&delay, NULL);
        active_handler = 0;
    }
    return reply_result;
}
static int exec_cmd(const char *path, ...) {
    assert(!strcmp(path, "/basebin/opainject")); ++inject_calls;
    if (event_mode) {
        dispatch_source_merge_data(current_source, 1);
        if (event_mode == 2) dispatch_semaphore_wait(handler_entered, DISPATCH_TIME_FOREVER);
    }
    return injector_error;
}
@interface DOJailbreaker : NSObject
- (NSError *)injectLaunchdHook;
@end
'''

CASES = r'''
static void reset(void) {
    assert(ports == 0 && attrs == 0 && !active_handler);
    current_source = nil;
    handler_entered = dispatch_semaphore_create(0);
    fail_allocate = fail_insert = fail_attr = fail_register = fail_spawn = 0;
    fail_wait = interrupt_wait = child_status = injector_error = source_failure = 0;
    receive_error = reply_result = event_mode = mobile = 0;
    destroys = spawn_calls = wait_calls = inject_calls = replies = 0;
}
static void run_case(BOOL success, int expected_inject, int expected_destroy) {
    @autoreleasepool {
        NSError *error = [[DOJailbreaker new] injectLaunchdHook];
        assert((error == nil) == success);
        assert(inject_calls == expected_inject && destroys == expected_destroy);
        assert(ports == 0 && attrs == 0 && !active_handler);
    }
}
int main(void) {
    reset(); mobile = 1; run_case(NO, 0, 0);
    reset(); fail_allocate = 5; run_case(NO, 0, 0);
    reset(); fail_insert = 5; run_case(NO, 0, 1);
    reset(); source_failure = 1; run_case(NO, 0, 1);
    reset(); fail_attr = EINVAL; run_case(NO, 0, 1);
    reset(); fail_register = EINVAL; run_case(NO, 0, 1);
    reset(); fail_spawn = ENOENT; run_case(NO, 0, 1);
    reset(); fail_wait = ECHILD; run_case(NO, 0, 1);
    reset(); child_status = 41 << 8; run_case(NO, 0, 1);
    reset(); child_status = SIGKILL; run_case(NO, 0, 1);
    reset(); injector_error = 256; run_case(NO, 1, 1);
    reset(); run_case(NO, 1, 1); // No handoff -> timeout and cancellation.
    reset(); event_mode = 1; receive_error = 5; run_case(NO, 1, 1);
    reset(); event_mode = 1; reply_result = -4; run_case(NO, 1, 1);
    reset(); event_mode = 1; reply_result = JBS_BOOMERANG_DONE;
    interrupt_wait = 2; run_case(YES, 1, 1); assert(wait_calls == 3 && replies == 1);
    // opainject fails while the server handler is still using primitives.
    // The method must await that handler before destroying its port/returning.
    reset(); event_mode = 2; injector_error = 256; run_case(NO, 1, 1); assert(replies == 1);
    // A subsequent attempt owns fresh retained state and can succeed.
    reset(); event_mode = 1; reply_result = JBS_BOOMERANG_DONE; run_case(YES, 1, 1);
    puts("PASS: injection failure gates, interrupted wait, timeout, cancellation during handler, fresh retry");
    return 0;
}
'''

# A declaration-only SDK substitute for local syntax checks, never linking or
# pretending to emulate Foundation/Mach/dispatch. Apple CI uses real headers.
SYNTAX_PREFIX = r'''
typedef int BOOL;
#define YES 1
#define NO 0
#define nil ((void *)0)
#define NULL ((void *)0)
#define true 1
typedef unsigned long uintptr_t;
typedef long long int64_t;
typedef int pid_t;
typedef unsigned mach_port_t;
typedef int kern_return_t;
typedef void *posix_spawnattr_t;
typedef unsigned long long dispatch_time_t;
typedef id dispatch_source_t;
typedef id dispatch_queue_t;
typedef id dispatch_semaphore_t;
typedef const void *dispatch_source_type_t;
#define MACH_PORT_NULL 0
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_MSG_TYPE_MAKE_SEND 20
#define KERN_SUCCESS 0
#define DISPATCH_QUEUE_SERIAL NULL
#define DISPATCH_SOURCE_TYPE_MACH_RECV NULL
#define DISPATCH_TIME_NOW 0
#define DISPATCH_TIME_FOREVER (~0ull)
#define NSEC_PER_SEC 1000000000ull
#define WIFEXITED(s) (((s)&127)==0)
#define WIFSIGNALED(s) (((s)&127)!=0 && ((s)&127)!=127)
#define WEXITSTATUS(s) (((s)>>8)&255)
#define WTERMSIG(s) ((s)&127)
#define EINTR 4
extern int errno;
__attribute__((objc_root_class)) @interface NSObject @end
@interface NSString : NSObject
+ (instancetype)stringWithFormat:(NSString *)format, ...;
- (NSString *)stringByDeletingLastPathComponent;
- (NSString *)stringByAppendingPathComponent:(NSString *)component;
@property (readonly) const char *UTF8String;
@property (readonly) const char *fileSystemRepresentation;
@end
@interface NSDictionary : NSObject
+ (instancetype)dictionaryWithObjects:(const id [])objects forKeys:(const id [])keys count:(unsigned long)count;
@end
@interface NSError : NSObject
+ (instancetype)errorWithDomain:(NSString *)domain code:(long)code userInfo:(NSDictionary *)info;
@property (readonly) NSString *description;
@end
extern NSString *const NSLocalizedDescriptionKey;
extern unsigned getuid(void), geteuid(void), getgid(void), getegid(void);
extern int printf(const char *, ...);
extern char *strerror(int);
extern mach_port_t mach_task_self(void);
extern kern_return_t mach_port_allocate(mach_port_t, int, mach_port_t *);
extern kern_return_t mach_port_insert_right(mach_port_t, mach_port_t, mach_port_t, int);
extern kern_return_t mach_port_destroy(mach_port_t, mach_port_t);
extern dispatch_semaphore_t dispatch_semaphore_create(long);
extern dispatch_queue_t dispatch_queue_create(const char *, void *);
extern dispatch_source_t dispatch_source_create(dispatch_source_type_t, uintptr_t, unsigned long, dispatch_queue_t);
extern void dispatch_source_set_event_handler(dispatch_source_t, void (^)(void));
extern void dispatch_source_set_cancel_handler(dispatch_source_t, void (^)(void));
extern void dispatch_resume(dispatch_source_t), dispatch_source_cancel(dispatch_source_t);
extern long dispatch_semaphore_signal(dispatch_semaphore_t);
extern long dispatch_semaphore_wait(dispatch_semaphore_t, dispatch_time_t);
extern dispatch_time_t dispatch_time(dispatch_time_t, int64_t);
extern int posix_spawnattr_init(posix_spawnattr_t *), posix_spawnattr_destroy(posix_spawnattr_t *);
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t *, unsigned);
extern int posix_spawn(pid_t *, const char *, const void *, const posix_spawnattr_t *, char *const *, char *const *);
extern pid_t waitpid(pid_t, int *, int);
@protocol OS_xpc_object @end
typedef NSObject<OS_xpc_object> *xpc_object_t;
extern xpc_object_t xpc_dictionary_create(const char *const *, const xpc_object_t *, unsigned long);
extern int xpc_pipe_receive(mach_port_t, xpc_object_t *);
extern int jbserver_received_boomerang_xpc_message(int *, xpc_object_t);
extern int exec_cmd(const char *, ...);
extern void roothide_stage_log(const char *, ...) __attribute__((format(printf, 1, 2)));
extern void logSpawnImageDiagnostics(const char *);
extern int gBoomerangServer;
#define JBS_BOOMERANG_DONE 9
#define JBROOT_PATH(path) path
#define jbinfo(field) "/test"
#define JBErrorCodeFailedLaunchdInjection -11
extern NSString *const JBErrorDomain;
#define JBErrorCodeFailedDeveloperMode -16
extern struct { BOOL preserveDeveloperMode; } testJailbreakInfo;
#define jbinfo_devmode(field) (testJailbreakInfo.field)
extern int enableDeveloperMode(void);
@interface DOEnvironmentManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isInstalledThroughTrollStore;
@end
@interface DOJailbreaker : NSObject
- (NSError *)injectLaunchdHook;
- (NSError *)ensureDevModeEnabled;
- (void)runWithError:(NSError **)error didRemoveJailbreak:(BOOL *)removed showLogs:(BOOL *)logs;
- (void)runStagesWithError:(NSError **)error didRemoveJailbreak:(BOOL *)removed showLogs:(BOOL *)logs;
@end
@interface DOUIManager : NSObject
+ (instancetype)sharedInstance;
- (NSString *)rootHideStageLogPath;
@end
@interface NSProcessInfo : NSObject
+ (instancetype)processInfo;
@property (readonly) NSString *operatingSystemVersionString;
@end
struct utsname { char machine[256]; };
extern int uname(struct utsname *);
extern int roothide_stage_begin(const char *, BOOL);
extern void roothide_stage_end(void);
extern void roothide_reboot_log(const char *, ...) __attribute__((format(printf, 1, 2)));
extern int roothide_reboot_log_configure(const char *);
extern void free(void *);
extern char *strdup(const char *);
extern char *testRebootLogPath;
#define ROOTHIDE_REBOOT_LOG_NAME "RootHideReboot.log"
#define ENOMEM 12
typedef unsigned long long uint64_t;
typedef unsigned char uint8_t;
typedef unsigned long size_t;
#define EIO 5
#define ENOENT 2
#define SYS_sysctlbyname 274
extern long syscall(int, ...);
extern size_t strlen(const char *);
#define ksymbol(name) ((uint64_t)0x1000)
#define ksymbol_txm(name) ((uint64_t)0x2000)
extern uint64_t kread64(uint64_t);
extern int kwrite8(uint64_t, uint8_t), kreadbuf(uint64_t, void *, unsigned long);
'''

WAIT_PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
typedef int pid_t;
#define WIFEXITED(s) (((s)&127)==0)
#define WIFSIGNALED(s) (((s)&127)!=0 && ((s)&127)!=127)
static int interruptions, wait_error, expected_status, calls;
static pid_t waitpid(pid_t pid, int *status, int options) {
    assert(pid == 123 && options == 0); ++calls;
    if (interruptions) { --interruptions; errno = EINTR; return -1; }
    if (wait_error) { errno = wait_error; return -1; }
    *status = expected_status; return pid;
}
'''
WAIT_CASES = r'''
int main(void) {
    int status = 0;
    interruptions = 3; expected_status = 41 << 8;
    assert(waitForLaunchdStash(123, &status) == 0 && status == (41 << 8) && calls == 4);
    calls = 0; expected_status = 9;
    assert(waitForLaunchdStash(123, &status) == 0 && status == 9 && calls == 1);
    calls = 0; wait_error = ECHILD;
    assert(waitForLaunchdStash(123, &status) == ECHILD && calls == 1);
    wait_error = 0; expected_status = 0;
    assert(waitForLaunchdStash(123, &status) == 0 && status == 0);
    puts("PASS: extracted wait helper preserves exits/signals, retries EINTR, returns wait errors");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path, help='Existing scratch directory (caller manages cleanup).')
    args = parser.parse_args()
    source = (ROOT / 'Application/Dopamine/Jailbreak/DOJailbreaker.m').read_text(encoding='utf-8')
    wait = extract(source, 'static int waitForLaunchdStash(')
    method = extract(source, '- (NSError *)injectLaunchdHook')
    scratch = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='launchd-injection-')
    with scratch as directory:
        temp = Path(directory)
        if args.zig:
            compiler = [str(args.zig), 'cc']
            obj = temp / 'syntax.m'
            helper = extract(source, 'static int enableDeveloperMode(').replace('jbinfo(', 'jbinfo_devmode(')
            wrapper = extract(source, '- (void)runWithError:').replace('gSystemInfo.rebootLogPath', 'testRebootLogPath')
            extra = extract(source, '- (NSError *)ensureDevModeEnabled').replace('jbinfo(', 'jbinfo_devmode(') + '\n' + wrapper
            syntax_prefix = SYNTAX_PREFIX.replace('extern int enableDeveloperMode(void);', '')
            obj.write_text(syntax_prefix + wait + '\n' + helper + '\n@implementation DOJailbreaker\n' + method + '\n' + extra + '\n@end\n', encoding='utf-8')
            subprocess.run([str(args.zig), 'clang', '-cc1', '-triple', 'arm64-apple-ios17.0.0',
                            '-x', 'objective-c', '-fobjc-runtime=ios-17.0.0', '-fobjc-arc', '-fblocks',
                            '-fobjc-exceptions', '-DNIGHTLY=1', '-DCOMMIT_HASH="test-sha"', '-Wall', '-Wextra',
                            '-Werror', '-Wno-incomplete-implementation', '-fsyntax-only', str(obj)], check=True)
            print('PASS: extracted injection, early stage-log wrapper and Developer Mode Objective-C/ARC syntax (SDK stub, nightly define)', flush=True)
            # Model the SDK's distinct XPC Objective-C type in the fixture too.
            # Using id for this missed a typedef/NSString conflict in Apple CI.
            fixture_prefix = SYNTAX_PREFIX
            for declaration in (
                'extern int xpc_pipe_receive(mach_port_t, xpc_object_t *);',
                'extern int jbserver_received_boomerang_xpc_message(int *, xpc_object_t);',
                'extern int exec_cmd(const char *, ...);',
                'extern void roothide_stage_log(const char *, ...) __attribute__((format(printf, 1, 2)));',
                'extern void logSpawnImageDiagnostics(const char *);',
                'extern int gBoomerangServer;',
                'extern NSString *const JBErrorDomain;',
                '#define jbinfo(field) "/test"',
            ):
                fixture_prefix = fixture_prefix.replace(declaration, '')
            interface_start = fixture_prefix.index('@interface DOJailbreaker : NSObject')
            interface_end = fixture_prefix.index('@end', interface_start) + len('@end')
            fixture_prefix = fixture_prefix[:interface_start] + fixture_prefix[interface_end:]
            fixture_prefix = fixture_prefix.replace('@interface NSObject @end', '@interface NSObject\n+ (instancetype)new;\n@end')
            fixture_prefix += '''
#define DISPATCH_SOURCE_TYPE_DATA_ADD NULL
#define EINVAL 22
#define ECHILD 10
#define SIGKILL 9
#define assert(x) ((void)sizeof(x))
struct timespec { long tv_sec, tv_nsec; };
extern int nanosleep(const struct timespec *, struct timespec *);
extern int strcmp(const char *, const char *);
extern void dispatch_source_merge_data(dispatch_source_t, unsigned long);
extern int puts(const char *);
'''
            obj.write_text(fixture_prefix + MOCKS + wait + '\n@implementation DOJailbreaker\n' + method + '\n@end\n' + CASES,
                           encoding='utf-8')
            subprocess.run([str(args.zig), 'clang', '-cc1', '-triple', 'arm64-apple-ios17.0.0',
                            '-x', 'objective-c', '-fobjc-runtime=ios-17.0.0', '-fobjc-arc', '-fblocks',
                            '-fobjc-exceptions', '-Wall', '-Wextra', '-Werror', '-fsyntax-only', str(obj)], check=True)
            print('PASS: Darwin fixture syntax with distinct SDK XPC object type (declarations only)', flush=True)
            harness = temp / 'wait.c'
            harness.write_text(WAIT_PREFIX + wait + WAIT_CASES, encoding='utf-8')
            binary = temp / 'wait.exe'
            subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror', str(harness), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=15)
            print('Dispatch/Mach runtime NOT exercised on Windows; run this test in Apple CI.')
        elif sys.platform == 'darwin':
            harness = temp / 'test.m'
            harness.write_text('#import <Foundation/Foundation.h>\n#include <dispatch/dispatch.h>\n'
                               '#include <xpc/xpc.h>\n'
                               '#include <mach/mach.h>\n#include <assert.h>\n#include <errno.h>\n#include <signal.h>\n'
                               '#include <stdbool.h>\n#include <stdio.h>\n'
                               '#include <spawn.h>\n#include <string.h>\n#include <sys/wait.h>\n'
                               '#include <time.h>\n' + MOCKS + wait + '\n@implementation DOJailbreaker\n' + method + '\n@end\n' + CASES,
                               encoding='utf-8')
            binary = temp / 'test'
            subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-fblocks', '-fobjc-exceptions',
                            '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                            '-framework', 'Foundation', str(harness), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=30)
        else:
            parser.error('Use macOS for dispatch regressions or --zig on Windows for limited local checks.')


if __name__ == '__main__':
    main()
