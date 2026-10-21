#!/usr/bin/env python3
"""Exercise diagnostic FD validation, ownership, terminal writer and query lifecycle.

Windows runs the extracted typed client with a transport model. macOS also
executes real POSIX file/descriptor operations and Foundation timeout handling.
No test establishes iOS sandbox access or a successful terminal session.
"""
import argparse
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from test_app_checkin import extract

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / 'BaseBin/libjailbreak/src'
UI = ROOT / 'Application/Dopamine/UI'
RUNTIME = ROOT / 'BaseBin/systemhook/src'
DIAGNOSTIC_SOURCES = [
    '.github/scripts/test_runtime_identity.py',
    '.github/scripts/test_terminal_diagnostics.py',
    '.github/scripts/test_roothide_diagnostic_export.py',
    'Application/Dopamine/UI/DOUIManager.m',
    'Application/Dopamine/UI/DODiagnosticLogQuery.h',
    'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c',
    'BaseBin/libjailbreak/src/jbclient_xpc.c',
    'BaseBin/libjailbreak/src/jbclient_xpc.h',
    'BaseBin/libjailbreak/src/jbserver_domains.h',
    'BaseBin/libjailbreak/src/diagnostic_log.h',
    'BaseBin/systemhook/Makefile',
    'BaseBin/systemhook/src/common/runtime_diagnostics.c',
    'BaseBin/systemhook/src/common/runtime_diagnostics.h',
    'BaseBin/systemhook/src/main.c',
    'BaseBin/systemhook/src/roothider_main.c',
]

CLIENT_TEST = r'''
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define JBS_DOMAIN_DOPAMINE 4
#define JBS_DOPAMINE_DIAGNOSTIC_LOG_FD 4
enum { XPC_TYPE_DICTIONARY, XPC_TYPE_INT64, XPC_TYPE_FD, XPC_TYPE_STRING };
typedef struct value { int type; } *xpc_object_t;
static struct value args={XPC_TYPE_DICTIONARY}, reply={XPC_TYPE_DICTIONARY};
static struct value status={XPC_TYPE_INT64}, descriptor={XPC_TYPE_FD};
static int missing, alloc_failure, no_reply, released, dup_calls, dup_result=47;
static int64_t response;
static uint64_t sent;
static xpc_object_t xpc_dictionary_create_empty(void) { return alloc_failure?NULL:&args; }
static void xpc_dictionary_set_uint64(xpc_object_t o,const char *k,uint64_t v) {
    assert(o==&args && !strcmp(k,"selector"));sent=v;
}
static xpc_object_t jbserver_xpc_send(int d,int a,xpc_object_t o) {
    assert(d==4 && a==4 && o==&args);return no_reply?NULL:&reply;
}
static void xpc_release(xpc_object_t o) { assert(o==&args || o==&reply);released++; }
static int xpc_get_type(xpc_object_t o) { return o->type; }
static xpc_object_t xpc_dictionary_get_value(xpc_object_t o,const char *k) {
    assert(o==&reply && o->type==XPC_TYPE_DICTIONARY);
    if(!strcmp(k,"result")) return missing==1?NULL:&status;
    assert(!strcmp(k,"log-fd"));return missing==2?NULL:&descriptor;
}
static int64_t xpc_dictionary_get_int64(xpc_object_t o,const char *k) {
    assert(o==&reply && !strcmp(k,"result"));return response;
}
static int xpc_dictionary_dup_fd(xpc_object_t o,const char *k) {
    assert(o==&reply && !strcmp(k,"log-fd"));dup_calls++;errno=EBADF;return dup_result;
}
// PRODUCTION
static void check(int expected,int fdExpected,int releases,int dups) {
    released=dup_calls=0;int fd=999;
    assert(jbclient_dopamine_diagnostic_log_fd(13,&fd)==expected);
    assert(fd==fdExpected && released==releases && dup_calls==dups);
}
int main(void) {
    assert(jbclient_dopamine_diagnostic_log_fd(0,NULL)==EINVAL);
    alloc_failure=1;check(ENOMEM,-1,0,0);alloc_failure=0;
    no_reply=1;check(EIO,-1,1,0);no_reply=0;
    reply.type=XPC_TYPE_STRING;check(EPROTO,-1,2,0);reply.type=XPC_TYPE_DICTIONARY;
    missing=1;check(EPROTO,-1,2,0);missing=0;
    status.type=XPC_TYPE_STRING;check(EPROTO,-1,2,0);status.type=XPC_TYPE_INT64;
    response=-1;check(EPROTO,-1,2,0);
    response=(int64_t)INT_MAX+1;check(EPROTO,-1,2,0);
    response=EACCES;check(EACCES,-1,2,0);response=0;
    missing=2;check(EPROTO,-1,2,0);missing=0;
    descriptor.type=XPC_TYPE_STRING;check(EPROTO,-1,2,0);descriptor.type=XPC_TYPE_FD;
    dup_result=-1;check(EBADF,-1,2,1);dup_result=47;
    check(0,47,2,1);assert(sent==13);
    return 0;
}
'''

FILES_TEST = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
static int wrong_owner;
static int diagnostic_fstat(int fd,struct stat *s) {
    int r=fstat(fd,s);if(!r)s->st_uid=wrong_owner?502:501;return r;
}
#define fstat diagnostic_fstat
#include "diagnostic_log.h"
#undef fstat
static const char *serverRoot;
#define jbinfo(field) serverRoot
// HANDLER
static uid_t test_geteuid(void) { return 501; }
#define geteuid test_geteuid
#define fstat diagnostic_fstat
#define ROOTHIDE_TERMINAL_DIAGNOSTICS 1
static const char *prefix;
#define ROOTHIDE_TERMINAL_DIAGNOSTIC_PREFIX prefix
#include "runtime_diagnostics.c"
#undef fstat
#undef geteuid
int main(int argc,char **argv) {
    assert(argc==2);char path[1024],alias[1024],writer[1024],output[8192];
    prefix=argv[1]; // writer path is separate from the fixed RPC files
    snprintf(writer,sizeof(writer),"%s-501.log",prefix);
    snprintf(path,sizeof(path),"%s/var/mobile/Library/Logs/CrashReporter/%s",argv[1],rh_diagnostic_log_name(5));
    int fd=123;
    assert(rh_diagnostic_log_open(argv[1],7,&fd)==EINVAL && fd==-1);
    assert(rh_diagnostic_log_open(argv[1],UINT64_MAX,&fd)==EINVAL && fd==-1);
    assert(rh_diagnostic_log_open(argv[1],0,NULL)==EINVAL);
    assert(rh_diagnostic_log_open(argv[1],5,&fd)==ENOENT && fd==-1);
    int w=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);assert(w>=0 && write(w,"LOG",3)==3);close(w);
    assert(!rh_diagnostic_log_open(argv[1],5,&fd) && fd>=0);
    assert((fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDONLY && (fcntl(fd,F_GETFD)&FD_CLOEXEC));
    assert(write(fd,"X",1)==-1 && errno==EBADF);close(fd);
    assert(dopamine_diagnostic_log_fd(14,&fd)==EINVAL && fd==-1);
    assert(dopamine_diagnostic_log_fd(12,&fd)==ENOENT && fd==-1);
    serverRoot=argv[1];assert(!dopamine_diagnostic_log_fd(12,&fd));close(fd);
    wrong_owner=1;assert(rh_diagnostic_log_open(argv[1],5,&fd)==EACCES && fd==-1);wrong_owner=0;
    snprintf(alias,sizeof(alias),"%s-alias",path);assert(link(path,alias)==0);
    assert(rh_diagnostic_log_open(argv[1],5,&fd)==EACCES && fd==-1);unlink(alias);
    assert(rename(path,alias)==0 && symlink(alias,path)==0);
    assert(rh_diagnostic_log_open(argv[1],5,&fd)!=0 && fd==-1);unlink(path);unlink(alias);
    assert(mkfifo(path,0600)==0);assert(rh_diagnostic_log_open(argv[1],5,&fd)==EACCES && fd==-1);unlink(path);
    assert(mkdir(path,0700)==0);assert(rh_diagnostic_log_open(argv[1],5,&fd)==EACCES && fd==-1);rmdir(path);
    char huge[2048];memset(huge,'a',sizeof(huge)-1);huge[sizeof(huge)-1]=0;
    assert(rh_diagnostic_log_open(huge,0,&fd)==ENAMETOOLONG && fd==-1);
    errno=EDOM;
    roothide_terminal_diagnostic("NewTermHelper","ignored",NULL,0,0,0);
    assert(access(writer,F_OK)!=0 && errno==ENOENT);
    errno=EDOM;
    roothide_terminal_diagnostic("NewTerm","spawn.end","/private/SECRET/login",13,234,7);
    assert(errno==EDOM);
    roothide_app_startup_diagnostic("-NewTermLoginHelper","constructor.begin",0);
    fd=open(writer,O_RDONLY);assert(fd>=0);ssize_t n=read(fd,output,sizeof(output)-1);assert(n>0);output[n]=0;close(fd);
    assert(strstr(output,"target=login result=13 child=234 errno=7"));
    assert(strstr(output,"terminal=NewTermLoginHelper event=constructor.begin"));
    assert(!strstr(output,"SECRET"));
    for(int i=0;i<200;i++) roothide_terminal_diagnostic("zsh","bounded",NULL,0,0,0);
    fd=open(writer,O_RDONLY);struct stat s;assert(!fstat(fd,&s) && s.st_size<30000);close(fd);
    off_t before=s.st_size;roothide_terminal_diagnostic("zsh","over-limit",NULL,0,0,0);
    assert(!stat(writer,&s) && s.st_size==before);
    // The per-file cap is independent of the per-process event cap.
    fd=open(writer,O_WRONLY);assert(fd>=0 && !ftruncate(fd,256*1024));close(fd);
    terminal_write(writer,"over-file-limit");assert(!stat(writer,&s) && s.st_size==256*1024);
    unlink(writer);assert(symlink(path,writer)==0);terminal_write(writer,"no-symlink");
    assert(access(path,F_OK)!=0);unlink(writer);
    assert(!mkfifo(writer,0600));terminal_write(writer,"no-fifo");unlink(writer);
    return 0;
}
'''

XPC_TEST = r'''
#include <xpc/xpc.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#define JBS_DOMAIN_DOPAMINE 4
#define JBS_DOPAMINE_DIAGNOSTIC_LOG_FD 4
static xpc_object_t reply;
static xpc_object_t jbserver_xpc_send(int domain,int action,xpc_object_t args) {
    assert(domain==4 && action==4 && xpc_dictionary_get_uint64(args,"selector")==5);
    return xpc_retain(reply);
}
// PRODUCTION
static int descriptor_count(void) {
    int count=0;for(int fd=0;fd<1024;fd++)if(fcntl(fd,F_GETFD)>=0)count++;return count;
}
int main(int argc,char **argv) {
    assert(argc==2);int source=open(argv[1],O_RDWR|O_CREAT|O_EXCL,0600);assert(source>=0);
    assert(write(source,"LOG",3)==3);close(source);source=open(argv[1],O_RDONLY);assert(source>=0);
    reply=xpc_dictionary_create_empty();xpc_dictionary_set_int64(reply,"result",0);
    xpc_dictionary_set_fd(reply,"log-fd",source);close(source);
    int before=descriptor_count();
    for(int i=0;i<500;i++) {
        int fd=-1;assert(!jbclient_dopamine_diagnostic_log_fd(5,&fd) && fd>=0);
        assert((fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDONLY);
        char data[4]={0};assert(pread(fd,data,3,0)==3 && data[0]=='L');close(fd);
    }
    assert(descriptor_count()==before);xpc_release(reply);
    reply=xpc_string_create("malformed");int fd=99;
    assert(jbclient_dopamine_diagnostic_log_fd(5,&fd)==EPROTO && fd==-1);xpc_release(reply);
    return 0;
}
'''

QUERY_TEST = r'''
#import <Foundation/Foundation.h>
#include <assert.h>
#include <stdatomic.h>
#include "DODiagnosticLogQuery.h"
static _Atomic int lateFD=-1, queryCalls=0;
static int makeLog(NSString *path,NSUInteger bytes) {
    NSMutableData *d=[NSMutableData dataWithLength:bytes];memset(d.mutableBytes,'x',bytes);
    assert([d writeToFile:path atomically:YES]);return open(path.fileSystemRepresentation,O_RDONLY);
}
int main(int argc,char **argv) {
    @autoreleasepool {
        assert(argc==2);NSString *path=[NSString stringWithUTF8String:argv[1]];
        int source=makeLog(path,70000);assert(source>=0);
        NSMutableArray *fds=[NSMutableArray new];
        NSString *report=DODiagnosticDescriptorLogs(^int(uint64_t selector,int *out){
            assert(selector<14);*out=dup(source);[fds addObject:@(*out)];return 0;
        },[NSProgress discreteProgressWithTotalUnitCount:14]);
        assert([report containsString:@"newest 65536 bytes"] && [report containsString:@"total byte limit"]);
        assert(report.length<530000 && fds.count==9);
        for(NSNumber *fd in fds) assert(fcntl(fd.intValue,F_GETFD)==-1 && errno==EBADF);
        int writer=open(path.fileSystemRepresentation,O_WRONLY);
        report=DODiagnosticDescriptorLogs(^int(uint64_t s,int *out){(void)s;*out=dup(writer);return 0;},[NSProgress discreteProgressWithTotalUnitCount:14]);
        assert([report containsString:@"not a readable regular descriptor"]);close(writer);
        report=DODiagnosticDescriptorLogs(^int(uint64_t s,int *out){(void)s;*out=dup(source);return EACCES;},[NSProgress discreteProgressWithTotalUnitCount:14]);
        assert([report containsString:@"result=13"]);
        NSProgress *cancelled=[NSProgress discreteProgressWithTotalUnitCount:14];[cancelled cancel];
        __block int calls=0;
        DODiagnosticDescriptorLogs(^int(uint64_t s,int *out){(void)s;(void)out;calls++;return 0;},cancelled);
        assert(!calls);
        NSString *fifo=[path stringByAppendingString:@".fifo"];assert(!mkfifo(fifo.fileSystemRepresentation,0600));
        int pipeFD=open(fifo.fileSystemRepresentation,O_RDONLY|O_NONBLOCK);assert(pipeFD>=0);
        report=DODiagnosticDescriptorLogs(^int(uint64_t s,int *out){(void)s;*out=dup(pipeFD);return 0;},[NSProgress discreteProgressWithTotalUnitCount:14]);
        assert([report containsString:@"not a readable regular descriptor"]);close(pipeFD);
        dispatch_semaphore_t release=dispatch_semaphore_create(0);
        __block int completions=0;
        assert(DODiagnosticLogQueryStart(.05,^int(uint64_t s,int *out){
            assert(s==0);atomic_fetch_add(&queryCalls,1);
            dispatch_semaphore_wait(release,DISPATCH_TIME_FOREVER);
            *out=dup(source);atomic_store(&lateFD,*out);return 0;
        },^(NSString *text){
            assert(NSThread.isMainThread && ++completions==1 && [text containsString:@"timed out"]);
            assert(!DODiagnosticLogQueryStart(1,^int(uint64_t s,int *out){(void)s;(void)out;abort();},^(NSString *t){(void)t;abort();}));
            dispatch_semaphore_signal(release);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{
                assert(completions==1 && atomic_load(&queryCalls)==1);
                int fd=atomic_load(&lateFD);assert(fd>=0 && fcntl(fd,F_GETFD)==-1 && errno==EBADF);
                assert(DODiagnosticLogQueryStart(1,^int(uint64_t s,int *out){(void)s;*out=-1;return ENOENT;},^(NSString *t){
                    assert(NSThread.isMainThread && [t containsString:@"unavailable"]);close(source);exit(0);
                }));
            });
        }));
        assert(!DODiagnosticLogQueryStart(1,^int(uint64_t s,int *out){(void)s;(void)out;abort();},^(NSString *t){(void)t;abort();}));
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),dispatch_get_main_queue(),^{abort();});
    }
    // Keep the process's main thread and Foundation main-thread identity.
    [[NSRunLoop mainRunLoop] run];
    return 1;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    client = (CLIENT / 'jbclient_xpc.c').read_text(encoding='utf-8')
    domain = (ROOT / 'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c').read_text(encoding='utf-8')
    handler = extract(domain, 'int dopamine_diagnostic_log_fd(')
    assert 'selector >= RH_DIAGNOSTIC_LOG_COUNT * 2' in handler
    assert 'rh_diagnostic_log_open(' in handler and 'read(' not in handler
    assert '.permissionHandler = dopamine_domain_allowed' in domain
    assert domain.count('.handler = dopamine_diagnostic_log_fd') == 1
    wrappers = (RUNTIME / 'main.c').read_text(encoding='utf-8')
    for name in ('int __posix_spawn_hook(', 'int __execve_hook('):
        body = extract(wrappers, name)
        assert body.count('RH_TERMINAL_DIAGNOSTIC') == 2 and 'return result;' in body
    query = (UI / 'DODiagnosticLogQuery.h').read_text(encoding='utf-8')
    assert 'dispatch_get_global_queue(QOS_CLASS_UTILITY' in query and 'static BOOL inFlight' in query
    if args.workdir:
        args.workdir.mkdir(parents=True, exist_ok=False)
    context = nullcontext(args.workdir) if args.workdir else tempfile.TemporaryDirectory(prefix='terminal-diagnostics-')
    with context as directory:
        temp = Path(directory)
        compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['xcrun', 'clang']
        flags = ['-Wall', '-Wextra', '-Werror']
        if sys.platform == 'darwin':
            flags += ['-D_DARWIN_C_SOURCE', '-fsanitize=address,undefined']
        source = temp / 'client.c'
        source.write_text(CLIENT_TEST.replace('// PRODUCTION', extract(client, 'int jbclient_dopamine_diagnostic_log_fd(')), encoding='utf-8')
        binary = temp / ('test.exe' if sys.platform == 'win32' else 'test')
        subprocess.run(compiler + flags + ['-std=gnu11', str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)
        print('PASS: extracted typed client rejects malformed replies and models duplicate-FD ownership', flush=True)
        if sys.platform != 'darwin':
            print('POSIX files, real XPC and Foundation timeout lifecycle NOT run; Apple CI/device validation required.')
            return
        (temp / 'var/mobile/Library/Logs/CrashReporter').mkdir(parents=True)
        source.write_text(FILES_TEST.replace('// HANDLER', handler), encoding='utf-8')
        subprocess.run(compiler + flags + ['-std=gnu11', '-I', str(CLIENT), '-I', str(RUNTIME / 'common'), str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(temp)], check=True, timeout=10)
        print('PASS: actual read-only opens, link/FIFO/type/owner refusal, terminal whitelist, errno and event cap', flush=True)
        source.write_text(XPC_TEST.replace('// PRODUCTION', extract(client, 'int jbclient_dopamine_diagnostic_log_fd(')), encoding='utf-8')
        subprocess.run(compiler + flags + [str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(temp / 'xpc.log')], check=True, timeout=10)
        print('PASS: real Apple XPC dictionaries transfer read-only descriptors; repeated dup/release does not leak', flush=True)
        include = temp / 'include/libjailbreak'
        include.mkdir(parents=True)
        (include / 'diagnostic_log.h').write_bytes((CLIENT / 'diagnostic_log.h').read_bytes())
        source = temp / 'query.m'
        source.write_text(QUERY_TEST, encoding='utf-8')
        subprocess.run(compiler + flags + ['-fobjc-arc', '-fblocks', '-framework', 'Foundation', '-I', str(UI), '-I', str(include.parent), str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(temp / 'query.log')], check=True, timeout=10,
                       env={**__import__('os').environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
        print('PASS: actual descriptor closure, byte limits, FIFO/write rejection, timeout, single worker, late result and re-entry', flush=True)
    receipt = {'pass': True, 'device_terminal_verified': False, 'real_xpc_transport_tested': False,
               'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in DIAGNOSTIC_SOURCES}}
    (ROOT / 'artifacts').mkdir(exist_ok=True)
    (ROOT / 'artifacts/terminal-diagnostics-tests.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
