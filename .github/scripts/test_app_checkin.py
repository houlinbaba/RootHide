#!/usr/bin/env python3
"""Execute production App check-in/grant handling and typed RootHide state.

The host model checks ownership and malformed/service-failure paths. It cannot
validate an iOS sandbox, credential offsets or the reported RootHide reboot.
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
        if depth == 0:
            return source[start:pos + 1]
    raise ValueError(signature)


PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef EPROTO
#define EPROTO 71
#endif
#ifndef ESTALE
#define ESTALE 116
#endif
#define JBS_DOMAIN_SYSTEMWIDE 1
#define JBS_SYSTEMWIDE_PROCESS_CHECKIN 3
#define JBS_DOMAIN_ROOTHIDE 6
#define JBS_ROOTHIDE_JAILBROKEN_CHECK 1
typedef enum { XPC_TYPE_INT64, XPC_TYPE_BOOL, XPC_TYPE_STRING } kind;
typedef struct fake { kind type; } *xpc_object_t;
static struct fake resultObject={XPC_TYPE_INT64}, stateObject={XPC_TYPE_BOOL};
static struct fake reply;
static bool no_reply, missing_result, missing_state, state=true;
static int server_result, replies_released, consumed, consume_failure=-1;
static bool consume_errno=true;
static const char *reply_root="/active/root", *reply_extensions="grant1|grant2|grant3";
static char *cached_root;
#define jbinfo(field) cached_root
static xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t args) {
    assert(!args);
    assert((domain==1 && action==3) || (domain==6 && action==1));
    return no_reply?NULL:&reply;
}
static xpc_object_t xpc_dictionary_get_value(xpc_object_t object,const char *key) {
    assert(object==&reply);
    if (!strcmp(key,"result")) return missing_result?NULL:&resultObject;
    if (!strcmp(key,"jailbroken")) return missing_state?NULL:&stateObject;
    abort();
}
static kind xpc_get_type(xpc_object_t o) { return o->type; }
static int64_t xpc_dictionary_get_int64(xpc_object_t o,const char *key) {
    assert(o==&reply && !strcmp(key,"result"));return server_result;
}
static bool xpc_dictionary_get_bool(xpc_object_t o,const char *key) {
    assert(o==&reply);
    return !strcmp(key,"jailbroken")?state:false;
}
static const char *xpc_dictionary_get_string(xpc_object_t o,const char *key) {
    assert(o==&reply);
    if(!strcmp(key,"root-path"))return reply_root;
    if(!strcmp(key,"sandbox-extensions"))return reply_extensions;
    if(!strcmp(key,"boot-uuid"))return "test-uuid";
    abort();
}
static void xpc_release(xpc_object_t o) { assert(o==&reply);replies_released++; }
static void roothide_stage_log(const char *format,...) { (void)format; }
static int allocations;
static char *owned_copy(const char *s) {
    size_t n=strlen(s)+1;char *p=malloc(n);assert(p);memcpy(p,s,n);allocations++;return p;
}
static void owned_free(void *p) { if(p){allocations--;free(p);} }
#define strdup owned_copy
#define free owned_free
static int64_t sandbox_extension_consume(const char *token) {
    assert(token && *token && !strchr(token,'|'));
    assert(!strncmp(token,"grant",5));
    if(consumed==consume_failure) { if(consume_errno)errno=EPERM;return -1; }
    consumed++;return consumed==2?0:consumed; /* zero is also a valid sandbox handle */
}
static void reset(void) {
    free(cached_root);cached_root=NULL;assert(!allocations);
    no_reply=missing_result=missing_state=false;state=true;server_result=0;
    resultObject.type=XPC_TYPE_INT64;stateObject.type=XPC_TYPE_BOOL;
    reply_root="/active/root";reply_extensions="grant1|grant2|grant3";
    consume_failure=-1;consume_errno=true;consumed=0;replies_released=0;
}
'''

CASES = r'''
int main(void) {
    reset();assert(jbclient_app_checkin()==0 && consumed==3 && replies_released==1);
    assert(cached_root && !strcmp(cached_root,"/active/root") && allocations==1);
    char *same=cached_root;consumed=0;
    assert(jbclient_app_checkin()==0 && cached_root==same && consumed==3 && allocations==1);
    reset();no_reply=true;assert(jbclient_app_checkin()==-1 && !cached_root && !consumed && !allocations);
    reset();server_result=ETIMEDOUT;assert(jbclient_app_checkin()==ETIMEDOUT && !cached_root && !allocations);
    reset();missing_result=true;assert(jbclient_app_checkin()==EPROTO && !allocations);
    reset();resultObject.type=XPC_TYPE_BOOL;assert(jbclient_app_checkin()==EPROTO && !allocations);
    const char *roots[]={NULL,"","relative/root"};
    for(unsigned i=0;i<3;i++) {reset();reply_root=roots[i];assert(jbclient_app_checkin()==EPROTO && !cached_root && !consumed && !allocations);}
    const char *tokens[]={NULL,"","|grant2","grant1||grant3","grant1|"};
    for(unsigned i=0;i<5;i++) {reset();reply_extensions=tokens[i];assert(jbclient_app_checkin()==EPROTO && !cached_root && !allocations);}
    for(int i=0;i<3;i++) {reset();consume_failure=i;assert(jbclient_app_checkin()==EPERM && consumed==i && !cached_root && !allocations);}
    reset();consume_failure=0;consume_errno=false;errno=EINVAL;
    assert(jbclient_app_checkin()==EACCES && !allocations);
    reset();cached_root=strdup("/other/root");
    assert(jbclient_app_checkin()==ESTALE && !strcmp(cached_root,"/other/root") && !consumed && allocations==1);
    reset();assert(jbclient_roothide_jailbroken());
    reset();no_reply=true;assert(!jbclient_roothide_jailbroken());
    reset();missing_result=true;assert(!jbclient_roothide_jailbroken());
    reset();missing_state=true;assert(!jbclient_roothide_jailbroken());
    reset();resultObject.type=XPC_TYPE_BOOL;assert(!jbclient_roothide_jailbroken());
    reset();stateObject.type=XPC_TYPE_STRING;assert(!jbclient_roothide_jailbroken());
    reset();server_result=-1;assert(!jbclient_roothide_jailbroken());
    reset();state=false;assert(!jbclient_roothide_jailbroken());
    reset();puts("PASS: production App check-in consumes each grant, retains confirmed root, frees errors and rejects malformed active-session replies");
    return 0;
}
'''

OBJC_PREFIX = r'''
#ifdef RH_CHECKIN_FOUNDATION
#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#else
typedef signed char BOOL;
typedef _Bool bool;
typedef unsigned long long uint64_t;
#define false 0
#define true 1
#define NULL ((void *)0)
#define YES ((BOOL)1)
#define NO ((BOOL)0)
__attribute__((objc_root_class)) @interface NSObject @end
#endif
static bool active;
static unsigned state_calls;
static bool jbclient_roothide_jailbroken(void) {state_calls++;return active;}
static void roothide_stage_log(const char *format, ...) {(void)format;}
extern void exit(int) __attribute__((noreturn));
#define EXIT_FAILURE 1
static int jbclient_root_set_mac_label(uint64_t a,uint64_t b,uint64_t *c) {(void)a;(void)b;(void)c;return 0;}
@interface DOEnvironmentManager : NSObject { BOOL _isJailbroken; }
- (BOOL)isJailbroken;
- (BOOL)isInstalledThroughTrollStore;
- (int)runUnsandboxed:(void (^)(void))block;
@end
@implementation DOEnvironmentManager
- (BOOL)isInstalledThroughTrollStore {return NO;}
'''

OBJC_CASES = r'''
@end
#ifdef RH_CHECKIN_FOUNDATION
#include <assert.h>
#include <stdio.h>
int main(void) {
    @autoreleasepool {
        active=false;DOEnvironmentManager *manager=[DOEnvironmentManager new];
        assert(![manager isJailbroken]);
        active=true;
        assert([manager isJailbroken]); /* no CS_PLATFORM_BINARY prerequisite */
        unsigned before=state_calls;
        assert([manager isJailbroken] && state_calls==before);
        __block unsigned calls=0;
        assert([manager runUnsandboxed:^{calls++;}]==0 && calls==1);
        puts("PASS: production state method recognizes a confirmed active session without App platform flags");
    }
    return 0;
}
#endif
'''

STARTUP_PREFIX = r'''
#ifdef RH_CHECKIN_FOUNDATION
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <unistd.h>
#else
typedef unsigned int uint32_t;
typedef unsigned long size_t;
typedef signed char BOOL;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
#define true 1
#define NULL ((void *)0)
__attribute__((objc_root_class)) @interface NSObject @end
@interface NSString : NSObject
@property (readonly) const char *fileSystemRepresentation;
@end
extern uid_t getuid(void), geteuid(void);
extern gid_t getgid(void), getegid(void);
extern pid_t getpid(void);
#endif
@interface DOUIManager : NSObject
+ (instancetype)sharedInstance;
- (NSString *)rootHideStageLogPath;
@end
@interface DOEnvironmentManager : NSObject
+ (instancetype)sharedManager;
@property (readonly) BOOL isJailbroken;
@end
extern int roothide_stage_begin(const char *, _Bool);
extern void roothide_stage_log(const char *, ...) __attribute__((format(printf,1,2)));
extern void roothide_stage_end(void);
extern int jbclient_app_checkin(void);
extern int csops(pid_t, unsigned int, void *, size_t);
#define CS_OPS_STATUS 0
#define CS_PLATFORM_BINARY 0x4000000
extern char *cached_root;
#define jbinfo(field) cached_root
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    app = (ROOT / 'Application/Dopamine/main.m').read_text(encoding='utf-8')
    assert app.index('rh_credential_helper_main(') < app.index('jbclient_app_checkin()')
    assert app.index('roothide_stage_begin(') < app.index('jbclient_app_checkin()') < app.index('app.launch.end') < app.index('roothide_stage_end()')
    assert 'jbclient_process_checkin(NULL' not in app
    server = (ROOT / 'BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c').read_text(encoding='utf-8')
    assert 'bool isDopamineApp = is_dopamine_app(procPath)' in server
    assert 'generate_sandbox_extensions(processToken, isPlatformProcess || isDopamineApp)' in server
    assert 'test_app_checkin.py' in (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    environment = (ROOT / 'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf-8')
    state = extract(environment, '- (BOOL)isJailbroken\n')
    unsandbox = extract(environment, '- (int)runUnsandboxed:')
    assert 'csops(' not in state
    assert unsandbox.index('@available(iOS 17.0') < unsandbox.index('return 0;') < unsandbox.index('jbclient_root_set_mac_label')
    client = (SOURCE / 'jbclient_xpc.c').read_text(encoding='utf-8')
    app_checkin = (SOURCE / 'app_checkin.c').read_text(encoding='utf-8')
    # systemhook links jbclient_*.c without info.c. The App-only wrapper must
    # stay in libjailbreak's full source set, not add a state dependency there.
    assert 'jbinfo(' not in client and 'gSystemInfo' not in client
    assert '#include "info.h"' not in client
    assert 'int jbclient_app_checkin(' not in client
    assert SOURCE / 'app_checkin.c' not in SOURCE.glob('jbclient_*.c')
    assert 'src/*.c' in (ROOT / 'BaseBin/libjailbreak/Makefile').read_text(encoding='utf-8')
    assert '../libjailbreak/src/jbclient_*.c' in (ROOT / 'BaseBin/systemhook/Makefile').read_text(encoding='utf-8')
    functions = extract(client, 'int jbclient_process_checkin(') + '\n' + extract(app_checkin, 'int jbclient_app_checkin(')
    functions += '\n' + extract((SOURCE / 'jbclient_roothide.c').read_text(encoding='utf-8'), 'bool jbclient_roothide_jailbroken()')
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
    scratch = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='app-checkin-')
    with scratch as directory:
        temp = Path(directory)
        c = temp / 'app_checkin.c'
        binary = temp / ('app_checkin.exe' if sys.platform == 'win32' else 'app_checkin')
        c.write_text(PREFIX + functions + CASES, encoding='utf-8')
        sanitizers = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
        subprocess.run(compiler + sanitizers + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        # Run the real state method body on all hosts, including the Windows
        # feedback workstation, without requiring an Objective-C runtime.
        state_model = temp / 'session_state.c'
        body = state[state.index('{'):]
        state_model.write_text('''#include <assert.h>
#include <stdbool.h>
typedef bool BOOL;
#define YES true
#define NO false
static bool _isJailbroken, active;
static unsigned calls;
static bool jbclient_roothide_jailbroken(void) { calls++; return active; }
static BOOL state(void)\n''' + body + '''
int main(void) {
    assert(!state() && calls == 1);
    active = true; assert(state() && calls == 2);
    active = false; assert(state() && calls == 2);
    _isJailbroken = false; assert(!state() && calls == 3);
    return 0;
}
''', encoding='utf-8')
        subprocess.run(compiler + sanitizers + ['-std=c11', '-Wall', '-Wextra', '-Werror', str(state_model), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        print('PASS: production state body retries inactive state, recognizes active service without platform flag and caches positive state')
        objc = temp / 'app_state.m'
        objc.write_text(OBJC_PREFIX + state + unsandbox + OBJC_CASES, encoding='utf-8')
        flags = ['-fobjc-arc', '-fblocks', '-fobjc-exceptions', '-Wall', '-Wextra', '-Werror']
        if sys.platform == 'darwin':
            subprocess.run(compiler + sanitizers + flags + ['-DRH_CHECKIN_FOUNDATION', '-framework', 'Foundation', str(objc), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=15)
        else:
            objc_compiler = [str(args.zig.resolve()), 'clang'] if args.zig else ['clang']
            subprocess.run(objc_compiler + ['-cc1', '-triple', 'arm64-apple-ios17.0.0', '-x', 'objective-c'] + flags + ['-fobjc-runtime=ios-17.0.0', '-fsyntax-only', str(objc)], check=True)
            print('PASS: production App state/unsandbox ARC syntax; Foundation/device execution awaits Apple CI.')
        start = app.index('    @autoreleasepool {\n        int logResult')
        end = app.index('\n    if ([DOEnvironmentManager sharedManager].isJailbroken)', start)
        startup = temp / 'app_launch.m'
        startup.write_text(STARTUP_PREFIX + '\nvoid test_app_launch(void) {\n' + app[start:end] + '\n}\n', encoding='utf-8')
        if sys.platform == 'darwin':
            syntax = compiler + flags + ['-DRH_CHECKIN_FOUNDATION']
        else:
            syntax = objc_compiler + ['-cc1', '-triple', 'arm64-apple-ios17.0.0', '-x', 'objective-c'] + flags + ['-fobjc-runtime=ios-17.0.0']
        subprocess.run(syntax + ['-DNIGHTLY=1', '-DCOMMIT_HASH="test-sha"', '-fsyntax-only', str(startup)], check=True)
        print('PASS: production launch/check-in snapshot ARC syntax with nightly build definition')


if __name__ == '__main__':
    main()
