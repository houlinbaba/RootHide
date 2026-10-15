#!/usr/bin/env python3
"""Check the first reboot across bootstrap credential restoration.

Runs production request code with deterministic failure injection. On Apple CI,
also runs the App's completion fragment and finalize under Foundation with a
fake reboot action. No test invokes reboot3 or proves device stability.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from test_reboot_handoff import function, MODEL, NATIVE

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / 'BaseBin/libjailbreak/src'
APP = ROOT / 'Application/Dopamine/Jailbreak'

MODEL_EXTRA = r'''
#include "userspace_reboot.h"
#define getuid model_uid
#define geteuid model_euid
#define getgid model_gid
#define getegid model_egid
#define write model_write
#define waitpid model_waitpid
#define nanosleep model_sleep
#define posix_spawn model_spawn
#define posix_spawn_file_actions_init model_actions_init
#define posix_spawn_file_actions_adddup2 model_actions_dup
#define posix_spawn_file_actions_addclose model_actions_close
#define posix_spawn_file_actions_destroy model_actions_destroy
#ifndef WNOHANG
#define WNOHANG 1
#endif
#ifndef WIFEXITED
#define WIFEXITED(s) (((s)&255)==0)
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(s) ((s)>>8)
#endif
typedef int posix_spawn_file_actions_t;
static unsigned ids[4];
static unsigned getuid(void){return ids[0];}
static unsigned geteuid(void){return ids[1];}
static unsigned getgid(void){return ids[2];}
static unsigned getegid(void){return ids[3];}
static int actions_live, action_step, fail_action, spawned, waits, writes;
static int write_interrupt, write_error, wait_interrupt, wait_error, child_status, child_stuck;
static void roothide_stage_log(const char *format,...) {(void)format;}
static int nanosleep(const struct timespec *p,void *unused){assert(p->tv_nsec==10000000);(void)unused;return 0;}
static int action_result(void){return ++action_step==fail_action?ENOMEM:0;}
static int posix_spawn_file_actions_init(posix_spawn_file_actions_t *a){int r=action_result();if(!r){*a=1;actions_live++;}return r;}
static int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *a,int from,int to){assert(*a==1 && from==10 && to==3);return action_result();}
static int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *a,int fd){assert(*a==1 && (fd==10 || fd==11));return action_result();}
static int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *a){assert(*a==1 && actions_live==1);actions_live--;return 0;}
static int posix_spawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *a,const void *attr,char *const argv[],char *const env[]){
    assert(*a==1 && !attr && ids[1]==0 && ids[3]==0);
    assert(!strcmp(path,"/basebin/jbctl") && !strcmp(argv[0],path));
    assert(!strcmp(argv[1],"reboot_userspace") && !strcmp(argv[2],"--waitfor") && !strcmp(argv[3],"3") && !argv[4]);
    assert(env && !strcmp(env[0],"TEST=1"));spawned++;
    int r=action_result();if(!r)*pid=42;return r;
}
static ssize_t write(int fd,const void *buffer,size_t n){
    assert(fd==11 && live[11] && n==1 && *(const char *)buffer=='w');
    for(int i=0;i<4;i++)assert(ids[i]==501);writes++;
    if(write_interrupt){write_interrupt--;errno=EINTR;return -1;}
    if(write_error){errno=write_error;return -1;}return 1;
}
static pid_t waitpid(pid_t pid,int *status,int options){
    assert(pid==42 && options==WNOHANG && !live[11]);waits++;
    if(wait_interrupt){wait_interrupt--;errno=EINTR;return -1;}
    if(wait_error){errno=wait_error;return -1;}
    if(child_stuck)return 0;*status=child_status;return pid;
}
static void reset_request(void){
    reset(0);live[10]=0;
    for(int i=0;i<4;i++)ids[i]=0;
    actions_live=action_step=fail_action=spawned=waits=writes=0;
    write_interrupt=write_error=wait_interrupt=wait_error=child_status=child_stuck=0;
}
static void restore_mobile(void){for(int i=0;i<4;i++)ids[i]=501;}
static void clean(void){assert(!actions_live);for(int i=0;i<32;i++)assert(!live[i]);}
static char *test_env[]={"TEST=1",NULL};
'''

CASES = r'''
int main(void){
    struct rh_userspace_reboot r=RH_USERSPACE_REBOOT_EMPTY;
    reset_request();restore_mobile();assert(rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env)==EPERM && !spawned);clean();
    reset_request();assert(rh_userspace_reboot_prepare(NULL,"/basebin/jbctl",test_env)==EINVAL);
    for(int failure=1;failure<=5;failure++){
        reset_request();fail_action=failure;
        assert(rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env)==ENOMEM);
        assert(r.pid==-1 && r.releaseFD==-1 && !writes);clean();
    }
    for(int i=0;i<4;i++){
        reset_request();assert(!rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env));
        restore_mobile();ids[i]=0;
        assert(rh_userspace_reboot_finish(&r)==EPERM && !writes && r.pid==-1);clean();
    }
    // Full protocol: prepare while root, no action before restoration, finish
    // after restoring original mobile identity, with no additional root RPC.
    reset_request();assert(!rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env));
    assert(!writes && !waits && spawned==1 && live[11] && !live[10]);
    assert(rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env)==EBUSY);
    restore_mobile();write_interrupt=wait_interrupt=1;
    assert(!rh_userspace_reboot_finish(&r) && writes==2 && waits==2);clean();
    assert(rh_userspace_reboot_finish(&r)==EINVAL && !rh_userspace_reboot_cancel(&r));
    reset_request();assert(!rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env));
    restore_mobile();child_status=ECANCELED<<8;
    assert(rh_userspace_reboot_cancel(&r)==ECANCELED && !writes);clean();
    reset_request();assert(!rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env));
    restore_mobile();write_error=EPIPE;assert(rh_userspace_reboot_finish(&r)==EPIPE);clean();
    reset_request();assert(!rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env));
    restore_mobile();child_status=EPERM<<8;assert(rh_userspace_reboot_finish(&r)==EPERM);clean();
    reset_request();assert(!rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env));
    restore_mobile();wait_error=ECHILD;assert(rh_userspace_reboot_finish(&r)==ECHILD);clean();
    reset_request();assert(!rh_userspace_reboot_prepare(&r,"/basebin/jbctl",test_env));
    child_stuck=1;assert(rh_userspace_reboot_cancel(&r)==ETIMEDOUT && waits<=5 && !writes);clean();
    puts("PASS: first reboot root preparation, mobile restoration, single-use release, failure cleanup and bounded cancellation");
    return 0;
}
'''

OBJC = r'''
typedef _Bool bool;
#define true ((_Bool)1)
typedef int pid_t;
typedef unsigned long NSUInteger;
typedef signed char BOOL;
#define YES ((BOOL)1)
#define NO ((BOOL)0)
#define nil ((id)0)
#define QOS_CLASS_USER_INITIATED 1
#define UIAlertControllerStyleAlert 1
#define UIAlertActionStyleDefault 1
#define JBROOT_PATH(path) path
extern char **environ;
extern unsigned getuid(void),geteuid(void),getgid(void);
extern void roothide_stage_log(const char *,...);
extern int roothide_stage_begin(const char *,bool);
extern void roothide_stage_end(void);
extern int printf(const char *,...);
typedef void *dispatch_queue_t;
extern dispatch_queue_t dispatch_get_main_queue(void),dispatch_get_global_queue(int,unsigned long);
extern void dispatch_async(dispatch_queue_t,void (^)(void));
__attribute__((objc_root_class)) @interface NSObject @end
@interface NSString : NSObject
@property(readonly) const char *fileSystemRepresentation;
+ (instancetype)stringWithFormat:(NSString *)format,...;
@end
@interface NSArray : NSObject
+ (instancetype)arrayWithObjects:(const id *)objects count:(NSUInteger)count;
@end
@interface NSDictionary : NSObject
+ (instancetype)dictionaryWithObjects:(const id *)objects forKeys:(const id *)keys count:(NSUInteger)count;
@end
@interface NSError : NSObject
@property(readonly) NSString *description;
+ (instancetype)errorWithDomain:(NSString *)domain code:(long)code userInfo:(NSDictionary *)info;
@end
@interface NSString (UTF8)
@property(readonly) const char *UTF8String;
@end
extern NSString *const NSPOSIXErrorDomain,*const NSLocalizedDescriptionKey;
@interface DOUIManager : NSObject
+ (instancetype)sharedInstance;
- (NSString *)rootHideStageLogPath;
- (void)sendLog:(NSString *)log debug:(BOOL)debug;
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

INTERFACE = r'''
@interface DOEnvironmentManager : NSObject {
    struct rh_userspace_reboot _preparedUserspaceReboot;
}
+ (instancetype)sharedManager;
- (int)prepareBootstrapUserspaceReboot;
- (void)cancelPreparedUserspaceReboot;
- (void)rebootUserspace;
- (int)spawnJbctlAsRootWithArgs:(NSArray *)args;
@end
@interface DOJailbreaker : NSObject { BOOL _bootstrapIdentityActive; }
- (NSError *)cleanUpPostExploitation;
- (void)finalize;
@end
'''

DARWIN_APP = r'''
#import <Foundation/Foundation.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include "userspace_reboot.h"
extern char **environ;
static unsigned test_identity;
static unsigned test_getid(void){return test_identity;}
#define getuid test_getid
#define geteuid test_getid
#define getgid test_getid
#define getegid test_getid
static const char *test_executable;
#define JBROOT_PATH(path) test_executable
static int finished, prepare_calls, restore_error, finish_result;
static void roothide_stage_log(const char *format,...) {(void)format;}
static NSString *DOLocalizedString(NSString *key){return key;}
@interface DOUIManager : NSObject
+ (instancetype)sharedInstance;
- (void)sendLog:(NSString *)log debug:(BOOL)debug;
@end
@implementation DOUIManager
+ (instancetype)sharedInstance { static DOUIManager *shared;if(!shared)shared=[self new];return shared; }
- (void)sendLog:(NSString *)log debug:(BOOL)debug{(void)log;(void)debug;}
@end
'''

DARWIN_METHODS = r'''
+ (instancetype)sharedManager { static DOEnvironmentManager *shared;if(!shared)shared=[self new];return shared; }
- (instancetype)init {if((self=[super init]))_preparedUserspaceReboot=RH_USERSPACE_REBOOT_EMPTY;return self;}
- (void)rebootUserspace {finished++;finish_result=rh_userspace_reboot_finish(&_preparedUserspaceReboot);}
@end
@implementation DOJailbreaker
- (instancetype)init {if((self=[super init]))_bootstrapIdentityActive=YES;return self;}
- (NSError *)cleanUpPostExploitation {
    assert(!finished && test_identity==0);
    if(restore_error) {
        [[DOEnvironmentManager sharedManager] cancelPreparedUserspaceReboot];
        return [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO userInfo:nil];
    }
    test_identity=501;_bootstrapIdentityActive=NO;return nil;
}
'''

DARWIN_CASES = r'''
int main(int argc,char **argv) {
    if(argc>1 && !strcmp(argv[1],"reboot_userspace"))return cmd_wait_for_handoff("3");
    @autoreleasepool {
        test_executable=argv[0];
        DOJailbreaker *app=[DOJailbreaker new];NSError *error=nil;
        [app checkCompletion:&error];assert(!error && prepare_calls==1 && !finished && test_identity==501);
        [app finalize];assert(finished==1 && finish_result==0);
        test_identity=0;restore_error=1;finished=0;app=[DOJailbreaker new];
        [app checkCompletion:&error];assert(error && !finished && prepare_calls==2);
        // Cancellation consumed the pending request; no old reboot can run.
        test_identity=501;[[DOEnvironmentManager sharedManager] rebootUserspace];
        assert(finish_result==EINVAL);
        puts("PASS: production App completion and finalize over real Darwin child/pipe; restore failure cancels; no reboot syscall");
    }
    return 0;
}
'''


def completion(app):
    stages = function(app, '- (void)runWithError:')
    return stages[stages.index('    // Restoration deliberately'):stages.rindex('}')]


def check_wiring(app, env):
    stages = function(app, '- (void)runWithError:')
    tail = completion(app)
    assert tail.index('prepareBootstrapUserspaceReboot') < tail.index('activation.cleanup.begin')
    assert tail.index('[self cleanUpPostExploitation]', tail.index('activation.cleanup.begin')) < tail.index('activation.complete')
    after_cleanup = tail[tail.index('activation.cleanup.end'):]
    assert after_cleanup.index('cancelPreparedUserspaceReboot') < after_cleanup.index('activation.complete')
    cleanup = function(app, '- (NSError *)cleanUpPostExploitation')
    assert cleanup.index('cancelPreparedUserspaceReboot') < cleanup.index('exit(EXIT_FAILURE)')
    assert stages.index('cancelPreparedUserspaceReboot') < stages.index('doExploitation')
    reboot = function(env, '- (void)rebootUserspace')
    assert 'prepared.pid > 0 ? rh_userspace_reboot_finish(&prepared)' in reboot
    prepare = function(env, '- (int)prepareBootstrapUserspaceReboot')
    assert 'runAsRoot' not in prepare and 'runUnsandboxed' not in prepare
    spawn = function(env, '- (int)spawnJbctlAsRootWithArgs:')
    assert 'if (rootResult != 0) spawnResult = rootResult;' in spawn
    assert 'if (sandboxResult != 0) spawnResult = sandboxResult;' in spawn
    assert 'return rootResult;' in function(env, '- (int)runAsRoot:')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else [shutil.which('clang') or 'clang']
    source = (SRC / 'userspace_reboot.c').read_text(encoding='utf-8')
    stripped = '\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
    util = (SRC / 'util.c').read_text(encoding='utf-8')
    create = function(util, 'int cmd_create_handoff_pipe(')
    app = (APP / 'DOJailbreaker.m').read_text(encoding='utf-8')
    env = (APP / 'DOEnvironmentManager.m').read_text(encoding='utf-8')
    check_wiring(app, env)
    # Reject the regression even if the C protocol itself still passes.
    try:
        check_wiring(app.replace('prepareBootstrapUserspaceReboot];', 'description];'), env)
    except (AssertionError, ValueError):
        pass
    else:
        raise AssertionError('missing App bootstrap preparation was accepted')
    print('PASS: activation prepares before cleanup, cancels on restore failure, finalize consumes the prepared child')
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='bootstrap-reboot-')
    with context as directory:
        tmp = Path(directory)
        tmp.mkdir(parents=True, exist_ok=True)
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(SRC)]
        sanitizer = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
        harness = tmp / 'bootstrap-reboot.c'
        # The shared pipe model contains read-side helpers used by its own test.
        model = MODEL.replace('static int poll(', 'static __attribute__((unused)) int poll(').replace('static ssize_t read(', 'static __attribute__((unused)) ssize_t read(')
        # Load native wait macros before the model's Windows-only fallbacks.
        # Apple stdlib headers can also include sys/wait.h indirectly.
        model_code = '#include <sys/types.h>\n#ifndef _WIN32\n#include <sys/wait.h>\n#endif\n' + model + MODEL_EXTRA + create + stripped + CASES
        harness.write_text(model_code, encoding='utf-8')
        binary = tmp / ('bootstrap-reboot.exe' if sys.platform == 'win32' else 'bootstrap-reboot')
        subprocess.run(compiler + sanitizer + flags + [str(harness), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        if args.zig and sys.platform != 'darwin':
            subprocess.run(compiler + ['-target', 'aarch64-macos'] + flags +
                           ['-c', str(harness), '-o', str(tmp / 'bootstrap-model-darwin.o')], check=True)
            print('PASS: the same bootstrap model compiles with Darwin sys/wait.h and -Werror')
        header = (SRC / 'userspace_reboot.h').read_text(encoding='utf-8')
        header = '\n'.join(line for line in header.splitlines() if not line.startswith('#include'))
        methods = '\n'.join(function(env, sig) for sig in ('- (void)rebootUserspace', '- (int)prepareBootstrapUserspaceReboot', '- (void)cancelPreparedUserspaceReboot'))
        probe = tmp / 'bootstrap-reboot-arc.m'
        probe.write_text(OBJC + header + INTERFACE + '@implementation DOEnvironmentManager\n' + methods + '\n@end\n'
                         + '@implementation DOJailbreaker\n- (void)checkCompletion:(NSError **)errOut {\n' + completion(app)
                         + '\n}\n' + function(app, '- (void)finalize') + '\n@end\n', encoding='utf-8')
        target = ['-target', 'aarch64-macos-none'] if args.zig else []
        subprocess.run(compiler + target + ['-fobjc-arc', '-fblocks', '-fobjc-exceptions', '-Werror', '-Wno-incomplete-implementation', '-c', str(probe), '-o', str(tmp / 'bootstrap-app.o')], check=True)
        print('PASS: production App completion, preparation, cancellation and asynchronous reboot compile with ARC')
        # Cross-compile the C production file with real Darwin headers. Avoid
        # util.h's unrelated kernel/XPC imports by declaring this one API.
        native = NATIVE + '\n#include "userspace_reboot.h"\n#include "roothide_stage.h"\n' + create + stripped
        harness.write_text(native, encoding='utf-8')
        targets = ('aarch64-macos',) if args.zig else (None,)
        for arch in targets:
            subprocess.run(compiler + (['-target', arch] if arch else []) + flags + ['-c', str(harness), '-o', str(tmp / 'bootstrap-native.o')], check=True)
        print('PASS: bootstrap request compiles with Darwin spawn/wait/time headers')
        if sys.platform == 'darwin':
            # Execute the production App success tail, prepare/cancel methods
            # and finalize. Only cleanup and the actual reboot action are faked.
            wait = function(util, 'int cmd_wait_for_handoff(')
            prepare = function(env, '- (int)prepareBootstrapUserspaceReboot')
            prepare = prepare.replace('return rh_userspace_reboot_prepare(', 'prepare_calls++; return rh_userspace_reboot_prepare(')
            prefix = NATIVE + '#include <stdbool.h>\n' + DARWIN_APP
            probe.write_text(prefix + create + wait + stripped + INTERFACE
                             + '@implementation DOEnvironmentManager\n' + prepare
                             + function(env, '- (void)cancelPreparedUserspaceReboot') + DARWIN_METHODS
                             + '- (void)checkCompletion:(NSError **)errOut {\n' + completion(app) + '\n}\n'
                             + function(app, '- (void)finalize') + '\n@end\n' + DARWIN_CASES, encoding='utf-8')
            subprocess.run(compiler + sanitizer + flags + ['-fobjc-arc', '-Wno-incomplete-implementation',
                           '-framework', 'Foundation', str(probe), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=20)
        print('LIMIT: device userspace reboot and stability remain unverified')


if __name__ == '__main__':
    main()
