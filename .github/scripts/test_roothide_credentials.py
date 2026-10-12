#!/usr/bin/env python3
"""Run production donor/parser/ref-transfer code with a deterministic XNU model.

The model exercises identity syscalls, immutable hash keys, reference ownership,
partial writes, donor timeouts and descriptor cleanup. It does not emulate SPTM
or validate a device's structure offsets. On macOS also compile the real dyld
syscall entry for both device architectures as part of the normal build.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'BaseBin/libjailbreak/src'

SYSCALLS = ['geteuid', 'setregid', 'setgroups', 'setegid', 'setreuid', 'seteuid',
            'getuid', 'getgid', 'getegid', 'getgroups', 'write', 'read', 'exit']


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for pos in range(opening, len(source)):
        depth += (source[pos] == '{') - (source[pos] == '}')
        if not depth:
            return source[start:pos + 1]
    raise ValueError(signature)


SPAWN_PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "credential_types.h"
#define pid_t rh_test_pid_t
#define posix_spawnattr_t rh_test_attr_t
#define kill rh_test_kill
typedef int pid_t;
typedef short posix_spawnattr_t;
struct _posix_spawn_args_desc { posix_spawnattr_t attrp; };
#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 128
#endif
#ifndef SIGCONT
#define SIGCONT 19
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
static int spawn_calls, patch_calls, continue_calls, kill_calls, patch_error, spawn_error;
static int versions, change_version;
static const char *envbuf_getenv(char *const env[],const char *key) {
    if(!env)return NULL;
    for(unsigned i=0;env[i];i++)if(!strncmp(env[i],key,strlen(key)) && env[i][strlen(key)]=='=')return env[i]+strlen(key)+1;
    return NULL;
}
static bool is_dopamine_app(const char *path) { return !strcmp(path,"/Dopamine.app/Dopamine"); }
static int posix_spawnattr_getflags(posix_spawnattr_t *a,short *f) { *f=*a;return 0; }
static int posix_spawnattr_setflags(posix_spawnattr_t *a,short f) { *a=f;return 0; }
static int __posix_spawn_orig_wrapper(pid_t *p,const char *path,struct _posix_spawn_args_desc *d,char *const argv[],char *const env[]) {
    (void)path;(void)argv;(void)env;assert(d->attrp & POSIX_SPAWN_START_SUSPENDED);
    spawn_calls++;if(spawn_error)return spawn_error;*p=42;return 0;
}
static int proc_get_pidversion(pid_t p) { assert(p==42);return change_version && versions++ ? 56 : 55; }
static int proc_patch_csflags(pid_t p) { assert(p==42);patch_calls++;return 0; }
static int roothide_patch_proc_ex(pid_t p,bool force) { assert(p==42 && force);patch_calls++;return patch_error; }
static int kill(pid_t p,int sig) { assert(p==42);if(sig==SIGCONT)continue_calls++;else{assert(sig==SIGKILL);kill_calls++;}return 0; }
'''

SPAWN_CASES = r'''
static void reset_spawn(void) { spawn_calls=patch_calls=continue_calls=kill_calls=patch_error=spawn_error=versions=change_version=0; }
int main(void) {
    char *mainEnv[]={RH_CREDENTIAL_MAIN_ONLY_ENV "=1",NULL};
    char *env[]={RH_CREDENTIAL_HELPER_ENV "=1",NULL};
    char *argv[]={"app",RH_CREDENTIAL_HELPER_ARG,NULL};
    struct _posix_spawn_args_desc d={POSIX_SPAWN_START_SUSPENDED};pid_t p=0;
    assert(!spawn_credential_helper(&p,"/Dopamine.app/Dopamine",&d,argv,mainEnv));
    assert(p==42 && spawn_calls==1 && !patch_calls && !continue_calls);
    assert(spawn_credential_helper(&p,"/setuid-tool",&d,argv,mainEnv)==EINVAL);
    assert(spawn_calls==1);
    reset_spawn();assert(!spawn_credential_helper(&p,"/setuid-tool",&d,argv,env));
    assert(p==42 && patch_calls==2 && !continue_calls && d.attrp==POSIX_SPAWN_START_SUSPENDED);
    reset_spawn();d.attrp=0;assert(!spawn_credential_helper(&p,"/setuid-tool",&d,argv,env));
    assert(continue_calls==1 && d.attrp==0);
    reset_spawn();patch_error=1;assert(spawn_credential_helper(&p,"/setuid-tool",&d,argv,env)==EIO);
    assert(kill_calls==1 && !continue_calls && d.attrp==0);
    reset_spawn();spawn_error=ENOENT;assert(spawn_credential_helper(&p,"/setuid-tool",&d,argv,env)==ENOENT);
    assert(!patch_calls && !kill_calls && d.attrp==0);
    reset_spawn();change_version=1;assert(spawn_credential_helper(&p,"/setuid-tool",&d,argv,env)==EIO);
    assert(!continue_calls && !kill_calls && d.attrp==0);
    return 0;
}
'''


def compile_dyld_entry(tmp, compiler, zig):
    source = (ROOT / 'BaseBin/dyldhook/src/reimpl.c').read_text(encoding='utf-8')
    raw = function(source, '__attribute__((naked)) int64_t msyscall_noerrno(')
    probe = tmp / 'dyld-entry.c'
    if sys.platform == 'darwin':
        probe.write_text('#include <stdint.h>\n' + raw + '''
#define RH_CREDENTIAL_SYSCALL(n,a,b,c) msyscall_noerrno(n,(uint64_t)(a),(uint64_t)(b),(uint64_t)(c),(uint64_t)0,(uint64_t)0,(uint64_t)0,(uint64_t)0,(uint64_t)0)
#include "credential_helper.h"
bool rh_test_dyld_entry(int argc,char *const argv[]) { return rh_credential_helper_main(argc,argv); }
''', encoding='utf-8')
        for arch in ('arm64', 'arm64e'):
            obj = tmp / (arch + '.o')
            subprocess.run(['xcrun', '--sdk', 'iphoneos', 'clang', '-arch', arch,
                            '-miphoneos-version-min=16.0', '-O2', '-fno-stack-check',
                            '-D_FORTIFY_SOURCE=0', '-Wall', '-Wextra', '-Werror',
                            '-I', str(SOURCE), '-c', str(probe), '-o', str(obj)], check=True)
            symbols = subprocess.check_output(['xcrun', 'nm', '-u', str(obj)], text=True)
            for forbidden in ('_memcmp', '_bcmp', '_cerror', '___error'):
                assert forbidden not in symbols, (arch, symbols)
        print('PASS: production early dyld helper compiles for arm64/arm64e without TLS errno or new comparison imports')
    elif zig:
        probe.write_text('typedef unsigned long long uint64_t;\ntypedef long long int64_t;\n' + raw + '''
int64_t rh_test_raw_entry(void) { return msyscall_noerrno(126,(uint64_t)501,(uint64_t)0,(uint64_t)0,(uint64_t)0,(uint64_t)0,(uint64_t)0,(uint64_t)0,(uint64_t)0); }
''', encoding='utf-8')
        subprocess.run(compiler + ['-target', 'aarch64-macos-none', '-ffreestanding', '-O2',
                                  '-Wall', '-Wextra', '-Werror', '-c', str(probe),
                                  '-o', str(tmp / 'raw-entry.o')], check=True)
        print('PASS: production raw syscall assembly cross-compiles for Darwin arm64; complete iOS helper compile remains for CI')

PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include "credential_types.h"
static long fake_syscall(int, uintptr_t, uintptr_t, uintptr_t);
#define RH_CREDENTIAL_SYSCALL(n,a,b,c) fake_syscall(n,(uintptr_t)(a),(uintptr_t)(b),(uintptr_t)(c))
#include "credential_helper.h"
#include "credential_refs.h"
// System libc headers may already declare these types and functions on macOS.
// Give the deterministic model its own namespace after including libc headers.
#define pid_t rh_test_pid_t
#define uid_t rh_test_uid_t
#define posix_spawnattr_t rh_test_spawnattr_t
#define posix_spawn_file_actions_t rh_test_actions_t
#define pthread_mutex_t rh_test_mutex_t
#define timespec rh_test_timespec
#define pollfd rh_test_pollfd
#define pthread_mutex_lock rh_test_mutex_lock
#define pthread_mutex_unlock rh_test_mutex_unlock
#define pipe rh_test_pipe
#define fcntl rh_test_fcntl
#define close rh_test_close
#define clock_gettime rh_test_clock_gettime
#define nanosleep rh_test_nanosleep
#define poll rh_test_poll
#define read rh_test_read
#define kill rh_test_kill
#define waitpid rh_test_waitpid
#define posix_spawnattr_init rh_test_spawnattr_init
#define posix_spawnattr_destroy rh_test_spawnattr_destroy
#define posix_spawnattr_setflags rh_test_spawnattr_setflags
#define posix_spawnattr_set_persona_np rh_test_persona
#define posix_spawnattr_set_persona_uid_np rh_test_persona_uid
#define posix_spawnattr_set_persona_gid_np rh_test_persona_gid
#define posix_spawn_file_actions_init rh_test_actions_init
#define posix_spawn_file_actions_destroy rh_test_actions_destroy
#define posix_spawn_file_actions_adddup2 rh_test_actions_dup2
#define posix_spawn_file_actions_addclose rh_test_actions_close
#define posix_spawn rh_test_spawn
typedef int pid_t;
typedef unsigned uid_t;
typedef int posix_spawnattr_t;
typedef int posix_spawn_file_actions_t;
typedef int pthread_mutex_t;
// The fake mutex is an integer regardless of the native pthread ABI.
#undef PTHREAD_MUTEX_INITIALIZER
#define PTHREAD_MUTEX_INITIALIZER 0
#ifndef WNOHANG
#define WNOHANG 1
#endif
#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 10
#endif
#ifndef POLLIN
#define POLLIN 1
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGCONT
#define SIGCONT 19
#endif
#ifndef POSIX_SPAWN_START_SUSPENDED
#define POSIX_SPAWN_START_SUSPENDED 128
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
struct timespec { long tv_sec, tv_nsec; };
struct pollfd { int fd; short events, revents; };
typedef void (^kernel_map_accessor)(void *);
// All production blocks here are synchronous stack blocks; no heap copies.
void *_NSConcreteStackBlock[32];
void _Block_object_assign(void *dst, const void *src, const int flags) { (void)flags; *(const void **)dst=src; }
void _Block_object_dispose(const void *src, const int flags) { (void)src; (void)flags; }
static struct { struct { struct { bool exists; } proc_ro,ucred_rw; } kernelStruct; } gSystemInfo;
#define OFF_proc_proc_ro 24
#define OFF_proc_svuid 60
#define OFF_proc_svgid 64
#define OFF_proc_ro_ucred 32
#define OFF_proc_ro_task_tokens 128
#define OFF_task_token_ro_data_audit_token 8
#define OFF_ucred_rw 0
#define OFF_ucred_ref 16
#define OFF_ucred_uid 24
#define OFF_ucred_ruid 28
#define OFF_ucred_svuid 32
#define OFF_ucred_groups 40
#define OFF_ucred_rgid 104
#define OFF_ucred_svgid 108
#define OFF_ucred_rw_weak_ref 0
#define koffsetof(s,m) OFF_##s##_##m
_Alignas(16) static unsigned char kmem[65536];
static bool descriptors[256];
static int fd_next, fd_count, fail_spawn, fail_persona, ready_mode, ready_cursor;
static int fail_map_at, map_calls, fail_write_at, writes, published_error;
static int bad_saved, helper_failure, helper_op, privilege_dropped, exit_code;
static int syscall_order[32], syscall_count, helper_groups_order;
static int64_t milliseconds;
static bool donor_alive, donor_syscalls_ready;
static struct rh_credential generated, donor_request;
static struct rh_credential_ready ready_message;
static uint64_t target=0x1000, donor_proc=0x1800, old_cred=0x3000, new_cred=0x4000;
static uint64_t old_rw=0x5000, new_rw=0x6000;
static void put64(uint64_t a,uint64_t v) { memcpy(kmem+a,&v,8); }
static void put32(uint64_t a,uint32_t v) { memcpy(kmem+a,&v,4); }
static uint64_t get64(uint64_t a) { uint64_t v; memcpy(&v,kmem+a,8); return v; }
static uint32_t get32(uint64_t a) { uint32_t v; memcpy(&v,kmem+a,4); return v; }
static uint64_t kread_ptr(uint64_t a) { assert(a+8<sizeof(kmem)); return get64(a); }
static int kreadbuf(uint64_t a,void *b,size_t n) { assert(a+n<sizeof(kmem)); memcpy(b,kmem+a,n); return 0; }
static int kwritebuf(uint64_t a,const void *b,size_t n) {
    assert(a+n<sizeof(kmem));
    // Hashed credential bytes and rw pointer/padding must never be written.
    assert(!(a>=old_cred && a<old_cred+128)); assert(!(a>=new_cred && a<new_cred+128));
    if (++writes==fail_write_at) return EIO;
    memcpy(kmem+a,b,n);
    if (a==0x2000+OFF_proc_ro_ucred && published_error) return EIO;
    return 0;
}
static int kwrite32(uint64_t a,uint32_t b) { return kwritebuf(a,&b,4); }
static int kwrite64(uint64_t a,uint64_t b) { return kwritebuf(a,&b,8); }
static uint64_t proc_ucred(uint64_t p) { return kread_ptr(kread_ptr(p+OFF_proc_proc_ro)+OFF_proc_ro_ucred); }
static uint64_t proc_self(void) { return target; }
static uint64_t proc_find(pid_t p) { return p==42 && donor_alive ? donor_proc : 0; }
static int proc_get_pidversion(pid_t p) { return p==42 && donor_alive ? 55 : 0; }
static void proc_allow_all_syscalls(uint64_t p) { assert(p==donor_proc);donor_syscalls_ready=true; }
static uint64_t kvtophys(uint64_t a) { return a; }
static int physaccess_mapped(uint64_t a,uint64_t n,kernel_map_accessor block) {
    assert(a+n<sizeof(kmem));
    assert(a==old_cred+16 || a==new_cred+16 || a==old_rw || a==new_rw);
    assert(n==(a==old_rw || a==new_rw ? 4 : 8));
    if (++map_calls==fail_map_at) return EIO;
    block(kmem+a); return 0;
}
static void roothide_stage_log(const char *f,...) { (void)f; }
static int pthread_mutex_lock(pthread_mutex_t *m) { assert(!*m); *m=1; return 0; }
static int pthread_mutex_unlock(pthread_mutex_t *m) { assert(*m); *m=0; return 0; }
static int open_fd(void) { assert(fd_next<256); int f=fd_next++; descriptors[f]=true; fd_count++; return f; }
static int pipe(int p[2]) { p[0]=open_fd(); p[1]=open_fd(); return 0; }
static int fcntl(int fd,int cmd,int min) { assert(descriptors[fd] && cmd==F_DUPFD_CLOEXEC); if(fd_next<min)fd_next=min; return open_fd(); }
static int close(int fd) { assert(fd>=0 && descriptors[fd]); descriptors[fd]=false; fd_count--; return 0; }
static int clock_gettime(int c,struct timespec *t) { assert(c==CLOCK_MONOTONIC); milliseconds+=50; t->tv_sec=(long)(milliseconds/1000);t->tv_nsec=(long)(milliseconds%1000)*1000000;return 0; }
static int nanosleep(const struct timespec *a,void *b) { (void)a;(void)b;return 0; }
static int poll(struct pollfd *p,unsigned n,int timeout) { assert(n==1 && descriptors[p->fd] && timeout>0 && timeout<=5000); if(ready_mode==1)return 0; if(ready_mode==2){errno=EINTR;return -1;}return 1; }
static intptr_t read(int fd,void *buf,size_t n) {
    assert(descriptors[fd]);
    if(ready_mode==3)return 0;
    size_t remaining=sizeof(ready_message)-(size_t)ready_cursor;
    if(n>remaining)n=remaining;
    if(ready_mode==4 && n>2)n=2;
    memcpy(buf,(char *)&ready_message+ready_cursor,n);ready_cursor+=(int)n;return (intptr_t)n;
}
static int resume_donor(void);
static int kill(pid_t p,int sig) {
    assert(p==42 && (sig==SIGKILL || sig==SIGCONT));
    if(sig==SIGKILL)donor_alive=false;
    else{assert(donor_syscalls_ready);resume_donor();}
    return 0;
}
static pid_t waitpid(pid_t p,int *status,int flags) { assert(p==42 && flags==WNOHANG); *status=0; return p; }
static int posix_spawnattr_init(posix_spawnattr_t *a) { *a=1;return 0; }
static int posix_spawnattr_destroy(posix_spawnattr_t *a) { assert(*a);*a=0;return 0; }
static int posix_spawnattr_setflags(posix_spawnattr_t *a,short f) { assert(*a && f==POSIX_SPAWN_START_SUSPENDED);return 0; }
int posix_spawnattr_set_persona_np(const posix_spawnattr_t *a,uid_t id,uint32_t f) { assert(*a && id==99 && f==1);return fail_persona; }
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *a,uid_t id) { assert(*a && !id);return 0; }
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *a,uid_t id) { assert(*a && !id);return 0; }
static int posix_spawn_file_actions_init(posix_spawn_file_actions_t *a) { *a=1;return 0; }
static int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *a) { assert(*a);*a=0;return 0; }
static int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *a,int fd,int to) { assert(*a && descriptors[fd] && fd>=10 && (to==3 || to==4));return 0; }
static int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *a,int fd) { assert(*a && descriptors[fd] && fd>=10);return 0; }
static void store_identity(uint64_t cred,const struct rh_credential *c) {
    put32(cred+24,c->uid);put32(cred+28,c->ruid);put32(cred+32,c->svuid);
    memcpy(kmem+cred+36,&c->ngroups,2);memcpy(kmem+cred+40,c->groups,c->ngroups*4);
    put32(cred+104,c->rgid);put32(cred+108,c->svgid);
}
static long fake_syscall(int n,uintptr_t a,uintptr_t b,uintptr_t c) {
    (void)c;
    if(n==SYS_geteuid)return generated.uid;
    if(n==SYS_getuid)return generated.ruid;
    if(n==SYS_getgid)return generated.rgid;
    if(n==SYS_getegid)return generated.gid;
    if(n==SYS_getgroups){assert(a>=generated.ngroups);memcpy((void *)b,generated.groups,generated.ngroups*4);return generated.ngroups;}
    if(n==SYS_exit){exit_code=(int)a;return 0;}
    if(n==SYS_write){assert(a==3 && c==sizeof(ready_message));memcpy(&ready_message,(void *)b,c);return (long)c;}
    if(n==SYS_read){assert(a==4 && c==1);return 0;}
    syscall_order[syscall_count++]=n;
    if(++helper_op==helper_failure)return -EIO;
    // XNU 10002 setreuid/setregid update saved only if it matches neither
    // requested argument (including the -1 sentinel). Enforce permission
    // checks too: the donor cannot seteuid to an arbitrary ID after dropping root.
    uint32_t x=(uint32_t)a, y=(uint32_t)b;
    if(n==SYS_setregid || n==SYS_setreuid){
        bool uid=n==SYS_setreuid;
        uint32_t real=uid?generated.ruid:generated.rgid;
        uint32_t effective=uid?generated.uid:generated.gid;
        uint32_t saved=uid?generated.svuid:generated.svgid;
        if(generated.uid && ((x!=UINT32_MAX && x!=real && x!=effective && x!=saved) ||
                             (y!=UINT32_MAX && y!=real && y!=effective && y!=saved)))return -EPERM;
        if(x!=UINT32_MAX)real=x;
        if(y!=UINT32_MAX)effective=y;
        if(saved!=x && saved!=y)saved=effective;
        if(uid){generated.ruid=real;generated.uid=effective;generated.svuid=saved;}
        else{generated.rgid=real;generated.gid=generated.groups[0]=effective;generated.svgid=saved;}
    }
    else if(n==SYS_setgroups){assert(generated.uid==0);generated.ngroups=(uint16_t)a;memcpy(generated.groups,(void *)b,a*4);generated.gid=generated.groups[0];helper_groups_order=syscall_count;}
    else if(n==SYS_setegid){if(generated.uid && x!=generated.rgid && x!=generated.svgid)return -EPERM;generated.gid=generated.groups[0]=x;}
    else if(n==SYS_seteuid){if(generated.uid && x!=generated.ruid && x!=generated.svuid)return -EPERM;generated.uid=x;privilege_dropped=1;}
    else assert(!"unknown syscall");
    return 0;
}
static int posix_spawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *a,const posix_spawnattr_t *attr,char *const argv[],char *const env[]) {
    assert(*a && *attr && !strcmp(path,"/Applications/Dopamine.app/Dopamine"));
    assert(!strcmp(env[0],RH_CREDENTIAL_HELPER_ENV "=1"));
    if(fail_spawn)return fail_spawn;
    *pid=42;donor_alive=true;
    int argc=0;while(argv[argc])argc++;
    assert(env[3] && !strcmp(env[3],RH_CREDENTIAL_MAIN_ONLY_ENV "=1"));
    int r=rh_credential_parse(argc,argv,&donor_request);assert(!r);
    return 0; // START_SUSPENDED: no identity syscalls before parent preparation.
}
static int resume_donor(void) {
    memset(&generated,0,sizeof(generated)); generated.ngroups=1;
    int r=rh_credential_apply(&donor_request);
    if(bad_saved)generated.svuid=123;
    store_identity(new_cred,&generated);
    ready_message=(struct rh_credential_ready){RH_CREDENTIAL_READY_MAGIC,r};
    return 0;
}
'''

SUFFIX = r'''
static struct rh_credential mobile={501,501,501,501,501,501,2,{501,20}};
static struct rh_credential root;
static unsigned char old_key[104];
static uint32_t initial_tokens[10];
static void reset(void) {
    memset(kmem,0,sizeof(kmem));memset(descriptors,0,sizeof(descriptors));
    fd_next=0;fd_count=0;fail_spawn=fail_persona=ready_mode=ready_cursor=0;
    fail_map_at=map_calls=fail_write_at=writes=published_error=bad_saved=0;
    helper_failure=helper_op=privilege_dropped=syscall_count=helper_groups_order=0;
    milliseconds=0;donor_alive=donor_syscalls_ready=false;exit_code=-1;
    gSystemInfo.kernelStruct.proc_ro.exists=gSystemInfo.kernelStruct.ucred_rw.exists=true;
    root=mobile;root.uid=root.gid=root.groups[0]=root.svuid=root.svgid=0;
    put64(target+24,0x2000);put64(donor_proc+24,0x2800);
    put64(0x2000+32,old_cred);put64(0x2800+32,new_cred);
    put64(old_cred,old_rw);put64(new_cred,new_rw);
    put64(old_cred+16,3);put64(new_cred+16,2);
    put32(old_rw,3);put32(new_rw,2);
    put32(old_rw+4,0xabcdefab);put32(new_rw+4,0xfedcbafe);
    put64(old_rw+8,old_cred);put64(new_rw+8,new_cred);
    store_identity(old_cred,&mobile);store_identity(new_cred,&root);
    memcpy(old_key,kmem+old_cred+24,sizeof(old_key));
    put32(target+60,mobile.svuid);put32(target+64,mobile.svgid);
    for(unsigned i=0;i<10;i++)initial_tokens[i]=0x11223000+i;
    memcpy(kmem+0x2000+128,initial_tokens,sizeof(initial_tokens));
}
static void assert_immutable(void) {
    assert(!memcmp(old_key,kmem+old_cred+24,sizeof(old_key)));
    assert(get32(old_rw+4)==0xabcdefab && get32(new_rw+4)==0xfedcbafe);
    assert(get64(old_rw+8)==old_cred && get64(new_rw+8)==new_cred);
    assert(fd_count==0 && !donor_alive);
}
static void assert_rolled_back(void) {
    assert_immutable();assert(proc_ucred(target)==old_cred);
    assert(get64(old_cred+16)==3 && get32(old_rw)==3);
    assert(get64(new_cred+16)==2 && get32(new_rw)==2);
    assert(get32(target+60)==mobile.svuid && get32(target+64)==mobile.svgid);
    assert(!memcmp(kmem+0x2000+128,initial_tokens,sizeof(initial_tokens)));
}
int main(void) {
    _Atomic uint32_t weak=1;
    assert(!rh_credential_ref32(&weak,false) && weak==1);
    assert(rh_credential_ref32(&weak,true) && weak==2);
    assert(rh_credential_ref32(&weak,false) && weak==1);
    weak=0;assert(!rh_credential_ref32(&weak,true));
    weak=0x0fffffff;assert(!rh_credential_ref32(&weak,true));
    _Atomic uint64_t strong=1;assert(rh_credential_ref64(&strong,false) && strong==0);
    assert(!rh_credential_ref64(&strong,false));
    assert(rh_credential_ref64(&strong,true) && strong==1);
    uint32_t number;
    assert(rh_credential_number("4294967295",&number) && number==UINT32_MAX);
    assert(!rh_credential_number("4294967296",&number));
    assert(!rh_credential_number("-1",&number));assert(!rh_credential_number("",&number));
    struct rh_credential invalid=mobile;invalid.ngroups=17;assert(!rh_credential_valid(&invalid));
    invalid=mobile;invalid.svuid=UINT32_MAX;assert(!rh_credential_valid(&invalid));
    char *normal[]={"app",NULL};assert(!rh_credential_helper_main(1,normal));
    char *malformed[]={"app",RH_CREDENTIAL_HELPER_ARG,NULL};
    memset(&generated,0,sizeof(generated)); assert(rh_credential_helper_main(2,malformed));assert(exit_code==1 && ready_message.error==EINVAL);

    reset();assert(!proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root));
    assert(proc_ucred(target)==new_cred);
    assert(get64(old_cred+16)==2 && get32(old_rw)==2);
    assert(get64(new_cred+16)==3 && get32(new_rw)==3);
    assert(get32(target+60)==0 && get32(target+64)==0);
    assert(get32(0x2000+128)==0 && get32(0x2000+132)==0);
    assert(get32(0x2000+136)==initial_tokens[2]);
    assert(get32(0x2000+140)==0 && get32(0x2000+144)==0);
    assert(get32(0x2000+148)==501 && get32(0x2000+152)==501);
    for(unsigned i=7;i<10;i++)assert(get32(0x2000+128+i*4)==initial_tokens[i]);
    assert(syscall_order[0]==SYS_setregid && syscall_order[syscall_count-1]==SYS_seteuid);
    assert(helper_groups_order>0);assert_immutable();
    // XNU can now release the old cached-thread refs and find the same hash key.
    assert(!memcmp(old_key,kmem+old_cred+24,sizeof(old_key)));

    reset();assert(!proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&mobile));assert(!writes && !map_calls);assert_rolled_back();
    // Exercise real/saved asymmetry, setuid programs, UI privilege transitions
    // and bootstrap restore against actual XNU saved-ID and permission rules.
    for(unsigned i=0;i<7;i++){
        reset();struct rh_credential c=mobile;
        switch(i){
        case 0:c.ruid=c.rgid=0;break; // real root, saved/effective mobile
        case 1:c.svuid=c.svgid=0;break; // UI mobile with saved root
        case 2:c.uid=c.gid=c.groups[0]=c.svuid=c.svgid=0;break; // setuid root
        case 3:c.uid=c.gid=c.groups[0]=c.svuid=c.svgid=500;break; // setuid other user
        case 4:c.uid=c.gid=c.groups[0]=0;break; // temporary root, saved mobile
        case 5:c.uid=c.ruid=c.svuid=c.gid=c.rgid=c.svgid=c.groups[0]=0;break; // bootstrap root
        case 6:c.uid=500;break; // effective outside real/saved pair
        }
        memset(&generated,0,sizeof(generated));generated.ngroups=1;
        assert(!rh_credential_apply(&c));assert(rh_credential_equal(&c,&generated));
    }
    for(int i=1;i<=7;i++){reset();helper_failure=i;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root)==EIO);assert_rolled_back();}
    reset();bad_saved=1;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root)==EACCES);assert_rolled_back();
    for(int i=1;i<=4;i++){reset();fail_map_at=i;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root));assert_rolled_back();}
    for(int i=1;i<=4;i++){reset();fail_write_at=i;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root));assert_rolled_back();}
    reset();published_error=1;assert(!proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root));assert(proc_ucred(target)==new_cred);assert_immutable();
    reset();fail_spawn=ENOENT;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root)==ENOENT);assert_rolled_back();
    reset();fail_persona=EPERM;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root)==EPERM);assert_rolled_back();
    reset();ready_mode=1;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root)==ETIMEDOUT);assert_rolled_back();
    reset();ready_mode=2;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root)==ETIMEDOUT);assert_rolled_back();
    reset();ready_mode=3;assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root)==EPIPE);assert_rolled_back();
    reset();ready_mode=4;assert(!proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root));assert_immutable();
    reset();put32(old_rw,1);assert(proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root));assert(get32(old_rw)==1 && get64(old_cred+16)==3);assert_immutable();
    // One process holder plus one live thread is a normal XNU state. The
    // long-term count may reach zero; the thread's weak ref keeps it alive.
    reset();put64(old_cred+16,1);put32(old_rw,2);
    assert(!proc_credential_set(target,"/Applications/Dopamine.app/Dopamine",&root));
    assert(get64(old_cred+16)==0 && get32(old_rw)==1);assert_immutable();
    puts("PASS: production credential donor, immutable keys, width-correct refs, metadata, rollback, saved-ID validation, timeout, EINTR, EOF, partial read, fd cleanup");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--tmpdir', type=Path)
    args = parser.parse_args()
    compiler = [str(args.zig), 'cc'] if args.zig else [shutil.which('clang') or 'clang']
    source = (SOURCE / 'credentials.c').read_text(encoding='utf-8')
    source = '\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
    with tempfile.TemporaryDirectory(prefix='roothide-credentials-', dir=args.tmpdir) as directory:
        tmp = Path(directory)
        (tmp / 'sys').mkdir()
        (tmp / 'sys/syscall.h').write_text('\n'.join(f'#define SYS_{name} {i + 1}' for i, name in enumerate(SYSCALLS)), encoding='utf-8')
        harness = tmp / 'test.c'
        harness.write_text(PREFIX + source + SUFFIX, encoding='utf-8')
        binary = tmp / ('test.exe' if args.zig else 'test')
        sanitizers = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
        subprocess.run(compiler + sanitizers + ['-std=gnu11', '-fblocks', '-Wall', '-Wextra', '-Werror',
                                  '-I', str(tmp), '-I', str(SOURCE), str(harness), '-o', str(binary)], check=True)
        test_env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'}
        subprocess.run([str(binary)], check=True, timeout=15, env=test_env)
        launchd = (ROOT / 'BaseBin/launchdhook/src/roothider.m').read_text(encoding='utf-8')
        spawn_source = tmp / 'spawn.c'
        spawn_source.write_text(SPAWN_PREFIX + function(launchd, 'static int spawn_credential_helper(') + SPAWN_CASES, encoding='utf-8')
        spawn_binary = tmp / ('spawn.exe' if sys.platform == 'win32' else 'spawn')
        subprocess.run(compiler + sanitizers + ['-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(SOURCE), str(spawn_source), '-o', str(spawn_binary)], check=True)
        subprocess.run([str(spawn_binary)], check=True, timeout=15, env=test_env)
        print('PASS: production donor spawn bypasses bootstrap dyld, forces local patch, preserves suspension, cleans failed child, rejects PID reuse')
        compile_dyld_entry(tmp, compiler, args.zig)


if __name__ == '__main__':
    main()
