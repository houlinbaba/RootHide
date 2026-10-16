#!/usr/bin/env python3
"""Executable limits of F1 candidates from XNU 10002.1.13, with inert services.

References must be unmodified fixed-revision snapshots. This executes selected
XNU and production C control flows, not an Apple kernel or live Mach syscall.
The default F1 acceptance remains FAIL even when observations match assertions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from test_privilege_first_failure import extract

ROOT=Path(__file__).resolve().parents[2]
PREFIX=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
typedef int pid_t,kern_return_t,kauth_cred_t,user_addr_t;
typedef unsigned u_int;
struct process {int pid,version,refs,signal;uint64_t unique;};
typedef struct process *proc_t;
struct task {bool bsd;int terminated;};
typedef struct task *task_t;
static struct process a={42,10,0,0,100},b={42,11,0,0,101},caller={1,1,0,0,1},*current=&a;
static struct task target_task={true,0},kernel_task={false,0};
struct proc_ident{int p_pid;uint64_t p_uniqueid;int p_idversion;};
struct kill_args{int posix,pid,signum;};
#define __unused __attribute__((unused))
#define NSIG 32
#define SIGKILL 9
#define SIGTERM 15
#define SIGCONT 19
#define AUDIT_ARG(...) ((void)0)
#define PROC_NULL NULL
#define TASK_NULL NULL
#define KERN_INVALID_ARGUMENT 4
#define KERN_FAILURE 5
#define TASK_POLICY_ATTRIBUTE 1
#define TASK_POLICY_TERMINATED 2
#define TASK_POLICY_ENABLE 3
static proc_t proc_find(int pid){if(!current || pid!=42)return NULL;current->refs++;return current;}
static void proc_rele(proc_t p){assert(p->refs>0);p->refs--;}
static uint64_t proc_uniqueid(proc_t p){return p->unique;}
static int proc_pidversion(proc_t p){return p->version;}
static proc_t pzfind(int pid){(void)pid;return NULL;}
static int kauth_cred_get(void){return 0;}
static int cansignal(proc_t c,int uc,proc_t p,int sig){(void)c;(void)uc;(void)p;(void)sig;return 1;}
static void psignal(proc_t p,int sig){p->signal=sig;}
static int killpg1(proc_t cp,int sig,int pgid,int all,int posix){(void)cp;(void)sig;(void)pgid;(void)all;(void)posix;return 0;}
static proc_t current_proc(void){return &caller;}
static task_t proc_task(proc_t p){(void)p;return &target_task;}
static void proc_set_task_policy(task_t t,int a,int b,int c){(void)t;(void)a;(void)b;(void)c;}
static void *get_bsdtask_info(task_t t){return t->bsd?(void*)1:NULL;}
static int task_terminate_internal(task_t t){t->terminated++;return 0;}
static int now_ms,patches,resumes,change_identity;
static int proc_get_pidversion(int p){assert(p==42);return current->version;}
static int proc_get_ppid(int p){assert(p==42);return 1;}
#define proc_get_path(p,b) "/fixture/child"
#define roothide_stage_log(...) ((void)0)
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
static int test_clock_gettime(int c,struct timespec *ts){(void)c;ts->tv_sec=now_ms/1000;ts->tv_nsec=(now_ms%1000)*1000000;return 0;}
#define clock_gettime test_clock_gettime
static int roothide_patch_proc_ex(int p,bool force){assert(p==42&&force);patches++;now_ms=11000;if(change_identity)current=&b;return 0;}
static int proc_patch_csflags(int p){assert(p==42);patches++;return 0;}
static int kill(int p,int s){assert(p==42&&s==SIGCONT);resumes++;return 0;}
'''
CASES=r'''
int main(void){
    struct proc_ident ident={42,100,10};proc_t held=proc_find_ident(&ident);
    assert(held==&a && a.refs==1);proc_rele(held);current=&b;
    assert(!proc_find_ident(&ident) && !b.refs);
    puts("kernel proc_find_ident rejects replacement and owns a reference; kernel-only primitive");
    current=&a;int observed=proc_get_pidversion(42);assert(observed==10);current=&b;
    struct kill_args args={1,42,SIGKILL};assert(!xnu_kill(&caller,&args,NULL));
    assert(b.signal==SIGKILL && !a.signal && !b.refs);
    puts("version-read then kill signals replacement after PID lookup race");
    int32_t signal=0;b.signal=0;assert(!proc_terminate(42,&signal));
    assert(b.signal==SIGTERM && signal==SIGTERM);
    puts("proc_terminate uses current PID occupant and may choose SIGTERM");
    assert(task_terminate(&target_task)==KERN_FAILURE && !target_task.terminated);
    assert(!task_terminate(&kernel_task) && kernel_task.terminated==1);
    puts("this XNU task_terminate entry rejects tasks with BSD proc; no target cancel guarantee");
    current=&a;now_ms=10000;assert(jailbreakd_patch_spawn_child(1,42,true,false,true,10,10000000000LL)==-1 && !patches);
    current=&a;now_ms=0;assert(jailbreakd_patch_spawn_child(1,42,true,false,true,10,10000000000LL)==-1);
    assert(patches==1 && !resumes && now_ms==11000);
    puts("expired before start is rejected; in-flight callback can finish after deadline with work already performed");
    patches=0;now_ms=0;change_identity=1;current=&a;
    assert(jailbreakd_patch_spawn_child(1,42,true,false,true,10,10000000000LL)==-1 && patches==1 && !resumes);
    puts("post-work identity check refuses resume but does not undo earlier work");
    puts("F1 ACCEPTANCE: FAIL; no validated identity-bound cancellation/fence/loss disposition");
    return 0;
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--zig',type=Path)
    p.add_argument('--references',type=Path,required=True);p.add_argument('--workdir',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();ref=a.references.resolve();folder=a.workdir.resolve()
    inputs={n:(ref/n).read_text(encoding='utf-8') for n in ['kern_sig.c','proc_info.c','kern_proc.c','task.c']}
    blobs={'kern_sig.c':'b7161599c96994d3db6008153e2996ce869abf98',
           'proc_info.c':'5c6546a6ea3bd32b2f3d208e0d29db23998f158b',
           'kern_proc.c':'d1e82985473ff74a46c3ae19a0ac0e52590921e3',
           'task.c':'216b6affbc484b49ea697a747b2e790846db62f9'}
    for n in inputs:
        raw=(ref/n).read_bytes()
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blobs[n], 'reference changed: '+n
    source=PREFIX+'\n#define kill xnu_kill\n'+extract(inputs['kern_sig.c'],'int\nkill(')+'\n#undef kill\n'
    source+=extract(inputs['proc_info.c'],'int\nproc_terminate(')+extract(inputs['kern_proc.c'],'proc_t\nproc_find_ident(')+extract(inputs['task.c'],'kern_return_t\ntask_terminate(')
    server=ROOT/'BaseBin/jailbreakd/src/server.m';s=server.read_text(encoding='utf-8')
    source+=extract(s,'static bool jailbreakd_spawn_patch_request_current(')+extract(s,'static int64_t jailbreakd_patch_spawn_child(')+CASES
    path=folder/'mechanisms.c';program=folder/('mechanisms.exe' if sys.platform=='win32' else 'mechanisms');path.write_text(source,encoding='utf-8')
    cc=[str(a.zig.resolve()),'cc'] if a.zig else ['cc']
    subprocess.run(cc+['-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-variable',str(path),'-o',str(program)],check=True)
    r=subprocess.run([str(program)],capture_output=True,text=True,timeout=10);print(r.stdout,r.stderr,end='')
    a.output.write_text(json.dumps(dict(provenance='fixed XNU source + independent inert host substitutes',xnu_commit='a653a70d861014a544bffa506779088605bbabac',
        input_sha256={n:hashlib.sha256((ref/n).read_bytes()).hexdigest() for n in inputs},server_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),
        mechanism_observations_match=r.returncode==0,f1_acceptance_pass=False,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2),encoding='utf-8')
    if r.returncode:raise RuntimeError('mechanism harness mismatch')
    return 1

if __name__=='__main__':sys.exit(main())
