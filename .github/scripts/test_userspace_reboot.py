#!/usr/bin/env python3
"""Exercise production reboot preparation/gating without requesting a reboot.

The deterministic model runs on Windows and macOS. Darwin also spawns this
test binary over real pipes; its child only validates the gate and exits.
Neither mode proves device reboot or launchd health.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'BaseBin/libjailbreak/src'


def extract(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for pos in range(opening, len(source)):
        depth += (source[pos] == '{') - (source[pos] == '}')
        if not depth:
            return source[start:pos + 1]
    raise ValueError(signature)


PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "userspace_reboot.h"
typedef int posix_spawn_file_actions_t;
#define ssize_t rh_test_ssize_t
typedef long long ssize_t;
#define timespec rh_test_timespec
struct timespec { long long tv_sec, tv_nsec; };
struct pollfd { int fd; short events, revents; };
#define F_DUPFD_CLOEXEC 1
#define F_SETNOSIGPIPE 2
#define POLLIN 1
#define POLLNVAL 32
#define CLOCK_MONOTONIC 1
#define WIFEXITED(s) (((s)&255)==0)
#define WEXITSTATUS(s) ((s)>>8)
static unsigned uid, gid;
static int step, fail_step, live[32], source_closed[2], action_reader, action_writer;
static int dup_actions, close_actions, actions_live, spawn_calls, waits, writes, polls;
static int write_interrupt, wait_interrupt, poll_interrupt, read_interrupt, wait_error;
static int write_error, zero_write, child_status, token_mode, timeout, bad_fd, time_error;
static long long current_ms;
static bool nosigpipe;
static unsigned getuid(void) { return uid; }
static unsigned geteuid(void) { return uid; }
static unsigned getgid(void) { return gid; }
static unsigned getegid(void) { return gid; }
static void roothide_stage_log(const char *format, ...) { (void)format; }
static int failing(void) { return ++step == fail_step; }
static int pipe(int fds[2]) {
    if(failing()){errno=EMFILE;return -1;}
    // Reproduce fd 3 allocation: dup2 must not overwrite a source writer.
    fds[0]=3;fds[1]=4;live[3]=live[4]=1;return 0;
}
static int fcntl(int fd, int cmd, int value) {
    if(failing()){errno=EMFILE;return -1;}
    if(cmd==F_DUPFD_CLOEXEC){assert(value==10 && (fd==3 || fd==4));live[fd+7]=1;return fd+7;}
    assert(cmd==F_SETNOSIGPIPE && fd==11 && value==1);nosigpipe=true;return 0;
}
static int close(int fd) {
    assert(fd>=0 && fd<32 && live[fd]);live[fd]=0;
    if(fd==3 || fd==4)source_closed[fd-3]++;return 0;
}
static int posix_spawn_file_actions_init(posix_spawn_file_actions_t *actions) {
    if(failing())return ENOMEM;*actions=1;actions_live++;return 0;
}
static int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *actions,int from,int to) {
    assert(*actions==1 && from==10 && to==3);if(failing())return EINVAL;
    dup_actions++;return 0;
}
static int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *actions,int fd) {
    assert(*actions==1 && (fd==10 || fd==11));if(failing())return EINVAL;
    if(fd==10)action_reader++;else action_writer++;close_actions++;return 0;
}
static int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *actions) {
    assert(*actions==1 && actions_live==1);actions_live--;return 0;
}
static int posix_spawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,
                       const void *attrs,char *const argv[],char *const env[]) {
    assert(!strcmp(path,"/basebin/jbctl") && *actions==1 && !attrs);
    assert(uid==0 && gid==0 && nosigpipe && dup_actions==1 && close_actions==2);
    assert(action_reader==1 && action_writer==1 && source_closed[0]==1 && source_closed[1]==1);
    assert(!strcmp(argv[0],path) && !strcmp(argv[1],"reboot_userspace"));
    assert(!strcmp(argv[2],"--waitfor") && !strcmp(argv[3],"3") && !argv[4]);
    assert(env && !strcmp(env[0],"TEST=1"));spawn_calls++;
    if(failing())return ENOENT;*pid=42;return 0;
}
static ssize_t write(int fd,const void *buffer,size_t count) {
    assert(fd==11 && live[fd] && count==1 && *(const char *)buffer=='w' && uid==501 && gid==501);
    assert(nosigpipe);writes++;
    if(write_interrupt){write_interrupt--;errno=EINTR;return -1;}
    if(write_error){errno=write_error;return -1;}return zero_write ? 0 : 1;
}
static pid_t waitpid(pid_t pid,int *status,int options) {
    assert(pid==42 && options==0 && !live[11]);waits++;
    if(wait_interrupt){wait_interrupt--;errno=EINTR;return -1;}
    if(wait_error){errno=wait_error;return -1;}*status=child_status;return pid;
}
static int clock_gettime(int clock,struct timespec *now) {
    assert(clock==CLOCK_MONOTONIC);if(time_error){errno=EIO;return -1;}
    now->tv_sec=current_ms/1000;now->tv_nsec=(current_ms%1000)*1000000;return 0;
}
static int poll(struct pollfd *item,unsigned long count,int ms) {
    assert(count==1 && item->fd==3 && item->events==POLLIN && ms>0 && ms<=60000);polls++;
    if(poll_interrupt){poll_interrupt--;current_ms+=30000;errno=EINTR;return -1;}
    if(timeout)return 0;item->revents=bad_fd?POLLNVAL:POLLIN;return 1;
}
static ssize_t read(int fd,void *buffer,size_t count) {
    assert(fd==3 && count==1);
    if(read_interrupt){read_interrupt--;errno=EINTR;return -1;}
    *(char *)buffer=token_mode==2?'x':'w';return token_mode==1?0:1;
}
'''

CASES = r'''
static void reset(void) {
    uid=gid=0;step=fail_step=dup_actions=close_actions=actions_live=spawn_calls=waits=writes=polls=0;
    write_interrupt=wait_interrupt=poll_interrupt=read_interrupt=wait_error=write_error=zero_write=0;
    child_status=token_mode=timeout=bad_fd=time_error=0;current_ms=0;nosigpipe=false;
    action_reader=action_writer=0;memset(live,0,sizeof(live));memset(source_closed,0,sizeof(source_closed));
}
static void clean(void) { assert(!actions_live);for(unsigned i=0;i<32;i++)assert(!live[i]); }
static char *env[]={"TEST=1",NULL};
static void prepare(struct rh_userspace_reboot *r) {
    assert(!rh_userspace_reboot_prepare(r,"/basebin/jbctl",env));assert(r->pid==42 && r->releaseFD==11);
    assert(!writes && !waits && live[11] && !live[10]);uid=gid=501;
}
int main(void) {
    struct rh_userspace_reboot r=RH_USERSPACE_REBOOT_EMPTY;
    reset();uid=501;assert(rh_userspace_reboot_prepare(&r,"/basebin/jbctl",env)==EPERM && !step);
    reset();gid=501;assert(rh_userspace_reboot_prepare(&r,"/basebin/jbctl",env)==EPERM && !step);
    reset();assert(rh_userspace_reboot_prepare(NULL,"/basebin/jbctl",env)==EINVAL);
    assert(rh_userspace_reboot_prepare(&r,"",env)==EINVAL);
    for(int failure=1;failure<=9;failure++) {
        reset();fail_step=failure;assert(rh_userspace_reboot_prepare(&r,"/basebin/jbctl",env));
        assert(r.pid==-1 && r.releaseFD==-1 && !writes && !waits);clean();
    }
    reset();prepare(&r);assert(rh_userspace_reboot_prepare(&r,"/basebin/jbctl",env)==EBUSY);
    uid=0;assert(rh_userspace_reboot_finish(&r)==EPERM && !writes && r.pid==-1);clean();
    reset();prepare(&r);
    write_interrupt=wait_interrupt=2;assert(!rh_userspace_reboot_finish(&r));
    assert(writes==3 && waits==3 && r.pid==-1 && r.releaseFD==-1);clean();
    assert(rh_userspace_reboot_finish(&r)==EINVAL);
    assert(!rh_userspace_reboot_cancel(&r));
    reset();prepare(&r);child_status=ECANCELED<<8;assert(rh_userspace_reboot_cancel(&r)==ECANCELED);
    assert(!writes && waits==1);clean();
    reset();prepare(&r);write_error=EPIPE;assert(rh_userspace_reboot_finish(&r)==EPIPE);clean();
    reset();prepare(&r);zero_write=1;assert(rh_userspace_reboot_finish(&r)==EIO);clean();
    reset();prepare(&r);child_status=EPERM<<8;assert(rh_userspace_reboot_finish(&r)==EPERM);clean();
    reset();prepare(&r);child_status=9;assert(rh_userspace_reboot_finish(&r)==EIO);clean();
    reset();prepare(&r);wait_error=ECHILD;assert(rh_userspace_reboot_finish(&r)==ECHILD);clean();
    reset();assert(!rh_userspace_reboot_wait(3));
    token_mode=1;assert(rh_userspace_reboot_wait(3)==ECANCELED); // App exits/cancels: never reboot on EOF.
    token_mode=2;assert(rh_userspace_reboot_wait(3)==ECANCELED);
    reset();timeout=1;assert(rh_userspace_reboot_wait(3)==ETIMEDOUT);
    reset();poll_interrupt=2;assert(rh_userspace_reboot_wait(3)==ETIMEDOUT && polls==2);
    reset();read_interrupt=2;assert(!rh_userspace_reboot_wait(3) && polls==3);
    reset();bad_fd=1;assert(rh_userspace_reboot_wait(3)==EBADF);
    reset();time_error=1;assert(rh_userspace_reboot_wait(3)==EIO);
    assert(rh_userspace_reboot_wait(-1)==EINVAL);
    puts("PASS: root preparation, post-restore handoff, all allocation/spawn failures, cancellation, EOF, deadline, EINTR, EPIPE, reaping");
    return 0;
}
'''

DARWIN = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static unsigned test_uid=0;
static unsigned mock_euid(void) { return test_uid; }
#define geteuid mock_euid
#define getegid mock_euid
#define getuid mock_euid
#define getgid mock_euid
'''

DARWIN_CASES = r'''
int main(int argc,char **argv) {
    if(argc>1 && !strcmp(argv[1],"reboot_userspace")) {
        int result=rh_userspace_reboot_wait(3);close(3);return result;
    }
    struct rh_userspace_reboot request=RH_USERSPACE_REBOOT_EMPTY;
    extern char **environ;
    assert(!rh_userspace_reboot_prepare(&request,argv[0],environ));
    test_uid=501;assert(!rh_userspace_reboot_finish(&request));
    test_uid=0;assert(!rh_userspace_reboot_prepare(&request,argv[0],environ));
    test_uid=501;assert(rh_userspace_reboot_cancel(&request)==ECANCELED);
    assert(request.pid==-1 && request.releaseFD==-1);
    puts("PASS: real Darwin child/pipe token handoff and EOF cancellation; no reboot syscall invoked");
    return 0;
}
'''

OBJC_PREFIX = r'''
typedef _Bool bool;
#define true ((_Bool)1)
typedef int pid_t;
typedef unsigned long NSUInteger;
typedef signed char BOOL;
#define YES ((BOOL)1)
#define NO ((BOOL)0)
#define NULL ((void *)0)
#define nil ((id)0)
#define QOS_CLASS_USER_INITIATED 1
#define UIAlertControllerStyleAlert 1
#define UIAlertActionStyleDefault 1
#define JBROOT_PATH(path) path
extern char **environ;
extern unsigned getuid(void), geteuid(void), getgid(void), getegid(void);
extern int close(int);
extern void roothide_stage_log(const char *, ...) __attribute__((format(printf,1,2)));
extern int roothide_stage_begin(const char *, bool);
extern int roothide_stage_duplicate_fd(void);
extern void roothide_stage_begin_from_fd(int);
extern void roothide_stage_end(void);
typedef void *dispatch_queue_t;
extern dispatch_queue_t dispatch_get_main_queue(void), dispatch_get_global_queue(int,unsigned long);
extern void dispatch_async(dispatch_queue_t, void (^)(void));
__attribute__((objc_root_class)) @interface NSObject @end
@interface NSString : NSObject
@property(readonly) const char *fileSystemRepresentation;
+ (instancetype)stringWithFormat:(NSString *)format, ...;
@end
@interface NSArray : NSObject
+ (instancetype)arrayWithObjects:(const id *)objects count:(NSUInteger)count;
@end
@interface NSDictionary : NSObject
+ (instancetype)dictionaryWithObjects:(const id *)objects forKeys:(const id *)keys count:(NSUInteger)count;
@end
@interface NSError : NSObject
+ (instancetype)errorWithDomain:(NSString *)domain code:(long)code userInfo:(NSDictionary *)info;
@end
extern NSString *const JBErrorDomain, *const NSLocalizedDescriptionKey;
#define JBErrorCodeFailedPrepareUserspaceReboot -17
#define JBErrorCodeExistingRootHideSession -18
extern bool jbclient_roothide_jailbroken(void);
@interface DOUIManager : NSObject
+ (instancetype)sharedInstance;
- (NSString *)rootHideStageLogPath;
@end
@interface NSThread : NSObject
+ (BOOL)isMainThread;
@end
@interface UIAlertAction : NSObject
+ (instancetype)actionWithTitle:(NSString *)title style:(int)style handler:(void (^)(UIAlertAction *))handler;
@end
@interface UIViewController : NSObject
@property(readonly) UIViewController *presentedViewController;
- (void)presentViewController:(UIViewController *)controller animated:(BOOL)animated completion:(void (^)(void))completion;
@end
@interface UIAlertController : UIViewController
+ (instancetype)alertControllerWithTitle:(NSString *)title message:(NSString *)message preferredStyle:(int)style;
- (void)addAction:(UIAlertAction *)action;
@end
@interface UIWindow : NSObject
@property(readonly) UIViewController *rootViewController;
@end
@interface UIApplication : NSObject
+ (instancetype)sharedApplication;
@property(readonly) UIWindow *keyWindow;
@end
extern NSString *DOLocalizedString(NSString *);
'''


def check_arc(temp, zig):
    header = (SOURCE / 'userspace_reboot.h').read_text(encoding='utf-8')
    header = '\n'.join(line for line in header.splitlines() if not line.startswith('#include'))
    environment = (ROOT / 'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf-8')
    methods = '\n'.join(extract(environment, signature) for signature in (
        '- (void)rebootUserspace', '- (int)prepareBootstrapUserspaceReboot', '- (void)cancelPreparedUserspaceReboot'))
    interface = '''
@interface DOEnvironmentManager : NSObject {
    struct rh_userspace_reboot _preparedUserspaceReboot;
    int _preparedUserspaceRebootLogFD;
}
+ (instancetype)sharedManager;
- (int)spawnJbctlAsRootWithArgs:(NSArray *)args;
- (BOOL)isInstalledThroughTrollStore;
- (int)prepareBootstrapUserspaceReboot;
- (void)cancelPreparedUserspaceReboot;
- (void)rebootUserspace;
@end
@interface DOJailbreaker : NSObject
- (NSError *)cleanUpPostExploitation;
- (NSError *)ensureFreshActivation;
@end
'''
    app = (ROOT / 'Application/Dopamine/Jailbreak/DOJailbreaker.m').read_text(encoding='utf-8')
    fragment = app[app.index('    // The iOS 17 App regains its original ucred'):app.index('    roothide_stage_log("activation.cleanup.begin");')]
    # Compile the unchanged production fragment with a local errOut so ARC
    # checks the new activation branch as well as the actual handoff methods.
    probe = temp / 'reboot-arc.m'
    probe.write_text(OBJC_PREFIX + header + interface + '@implementation DOEnvironmentManager\n' + methods + '\n@end\n'
                     + '@implementation DOJailbreaker\n' + extract(app, '- (NSError *)ensureFreshActivation')
                     + '\n- (void)checkPreparation:(NSError **)errOut {\n' + fragment + '\n}\n@end\n', encoding='utf-8')
    compiler = [str(zig.resolve()), 'clang'] if zig else ['clang']
    subprocess.run(compiler + ['-cc1', '-triple', 'arm64-apple-ios17.0.0', '-x', 'objective-c',
                              '-fobjc-runtime=ios-17.0.0', '-fobjc-arc', '-fblocks', '-fobjc-exceptions',
                              '-Wall', '-Wextra', '-Werror', '-Wno-incomplete-implementation', '-fsyntax-only', str(probe)], check=True)
    print('PASS: production App preparation, cancellation, asynchronous handoff and activation branch ARC syntax (SDK declarations)')

LOG_PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#define F_DUPFD_CLOEXEC 1
static int gStageLock, gStageFD=5, close_count, duplicate_error;
static bool gStageActive=true;
static void pthread_mutex_lock(int *lock) { assert(!*lock);*lock=1; }
static void pthread_mutex_unlock(int *lock) { assert(*lock);*lock=0; }
static int fcntl(int fd,int command,int base) {
    assert(gStageLock && fd==5 && command==F_DUPFD_CLOEXEC && base==10);
    errno=EMFILE;return duplicate_error?-1:10;
}
static int close(int fd) { assert(gStageLock && (fd==5 || fd==10));close_count++;errno=EIO;return 0; }
'''
LOG_CASES = r'''
int main(void) {
    errno=ERANGE;int retained=roothide_stage_duplicate_fd();assert(retained==10 && errno==ERANGE);
    roothide_stage_end();assert(gStageFD==-1 && !gStageActive && close_count==1 && errno==ERANGE);
    roothide_stage_begin_from_fd(retained);assert(gStageFD==10 && gStageActive && errno==ERANGE);
    roothide_stage_begin_from_fd(retained);assert(close_count==1);
    roothide_stage_end();assert(close_count==2 && gStageFD==-1 && errno==ERANGE);
    assert(roothide_stage_duplicate_fd()==-1 && errno==ERANGE);
    gStageFD=5;duplicate_error=1;assert(roothide_stage_duplicate_fd()==-1 && gStageFD==5 && errno==ERANGE);
    roothide_stage_begin_from_fd(-1);assert(gStageActive && gStageFD==-1 && close_count==3 && errno==ERANGE);
    puts("PASS: retained log descriptor ownership, no double close, duplicate failure and errno preservation");
    return 0;
}
'''


def check_wiring():
    app = (ROOT / 'Application/Dopamine/Jailbreak/DOJailbreaker.m').read_text(encoding='utf-8')
    stages = extract(app, '- (void)runStagesWithError:')
    assert stages.index('prepareBootstrapUserspaceReboot') < stages.index('activation.cleanup.begin')
    assert stages.index('activation.cleanup.end') < stages.index('activation.complete')
    preparation = stages[stages.index('    // The iOS 17 App regains its original ucred'):stages.index('activation.cleanup.begin')]
    assert 'isInstalledThroughTrollStore' not in preparation
    assert stages.index('ensureFreshActivation') < stages.index('gatherSystemInformation') < stages.index('doExploitation')
    assert 'if (!removeJailbreakEnabled) {\n        *errOut = [self ensureFreshActivation];\n        if (*errOut) return;' in stages
    cleanup = extract(app, '- (NSError *)cleanUpPostExploitation')
    assert cleanup.index('cancelPreparedUserspaceReboot') < cleanup.index('exit(EXIT_FAILURE)')
    environment = (ROOT / 'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf-8')
    preparation = extract(environment, '- (int)prepareBootstrapUserspaceReboot')
    assert 'runAsRoot' not in preparation and 'runUnsandboxed' not in preparation
    assert 'roothide_stage_duplicate_fd()' in preparation
    reboot = extract(environment, '- (void)rebootUserspace')
    assert 'prepared.pid > 0 ? rh_userspace_reboot_finish(&prepared)' in reboot
    assert 'roothide_stage_begin_from_fd(preparedLogFD)' in reboot
    jbctl = (ROOT / 'BaseBin/jbctl/src/main.m').read_text(encoding='utf-8')
    assert 'rh_userspace_reboot_wait(fd)' in jbctl and 'if (result) return result;' in jbctl
    assert 'return result < 0 ? (errno ?: EIO) : result;' in jbctl
    workflow = (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    assert 'python3 .github/scripts/test_userspace_reboot.py' in workflow
    ui = (ROOT / 'Application/Dopamine/UI/DOUIManager.m').read_text(encoding='utf-8')
    assert 'NSHomeDirectory()' not in extract(ui, '- (NSString *)rootHideStageLogPath')

FRESH_DARWIN = r'''
#import <Foundation/Foundation.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#define JBErrorCodeExistingRootHideSession -18
static NSString *const JBErrorDomain=@"test";
static bool active;
static bool jbclient_roothide_jailbroken(void) { return active; }
static void roothide_stage_log(const char *format,...) { (void)format; }
static NSString *DOLocalizedString(NSString *key) { return key; }
@interface DOJailbreaker : NSObject
- (NSError *)ensureFreshActivation;
@end
'''
FRESH_CASES = r'''
int main(void) {
    @autoreleasepool {
        DOJailbreaker *jailbreaker=[DOJailbreaker new];
        active=false;assert(![jailbreaker ensureFreshActivation]);
        active=true;NSError *error=[jailbreaker ensureFreshActivation];
        assert(error && error.code==-18 && [error.domain isEqualToString:JBErrorDomain]);
        assert([error.localizedDescription isEqualToString:@"Jailbreak_Reboot_Before_Retry"]);
        active=false;assert(![jailbreaker ensureFreshActivation]);
        puts("PASS: production activation preflight accepts a fresh boot and rejects an existing RootHide session");
    }
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    check_wiring()
    production = (SOURCE / 'userspace_reboot.c').read_text(encoding='utf-8')
    stripped = '\n'.join(line for line in production.splitlines() if not line.startswith('#include'))
    scratch = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='userspace-reboot-')
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
    with scratch as directory:
        temp = Path(directory)
        harness = temp / 'reboot.c'
        binary = temp / ('reboot.exe' if sys.platform == 'win32' else 'reboot')
        harness.write_text(PREFIX + stripped + CASES, encoding='utf-8')
        sanitizer = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(SOURCE)]
        subprocess.run(compiler + sanitizer + flags + [str(harness), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        check_arc(temp, args.zig)
        logger = (SOURCE / 'roothide_stage.c').read_text(encoding='utf-8')
        log_helpers = '\n'.join(extract(logger, signature) for signature in (
            'int roothide_stage_duplicate_fd(', 'void roothide_stage_begin_from_fd(', 'void roothide_stage_end('))
        harness.write_text(LOG_PREFIX + log_helpers + LOG_CASES, encoding='utf-8')
        subprocess.run(compiler + sanitizer + flags + [str(harness), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        if sys.platform == 'darwin':
            harness.write_text(DARWIN + production + DARWIN_CASES, encoding='utf-8')
            subprocess.run(compiler + sanitizer + flags + [str(harness), str(SOURCE / 'roothide_stage.c'), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=15)
            app = (ROOT / 'Application/Dopamine/Jailbreak/DOJailbreaker.m').read_text(encoding='utf-8')
            objc = temp / 'preflight.m'
            objc.write_text(FRESH_DARWIN + '@implementation DOJailbreaker\n' + extract(app, '- (NSError *)ensureFreshActivation')
                            + '\n@end\n' + FRESH_CASES, encoding='utf-8')
            subprocess.run(compiler + sanitizer + ['-fobjc-arc', '-Wall', '-Wextra', '-Werror',
                                                  '-framework', 'Foundation', str(objc), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=15)
        else:
            print('Real Darwin spawn/pipe and device reboot remain for Apple CI/device validation.')


if __name__ == '__main__':
    main()
