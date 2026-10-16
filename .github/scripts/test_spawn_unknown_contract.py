#!/usr/bin/env python3
"""Independently rebuilt F1 contract probe; default gate currently MUST FAIL.

Runs extracted production reply classification and launchd posthook, with inert
XPC/spawn/signal substitutes. Transport outcomes are injected, not live XPC races.
It is deliberately NOT wired into CI as a passing repair acceptance test.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from test_unrestrict_contract import extract

ROOT = Path(__file__).resolve().parents[2]

PREFIX = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#ifndef SIGCONT
#define SIGCONT 19
#endif
#ifndef SIGQUIT
#define SIGQUIT 3
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 6
#endif
#define JBD_MSG_SPAWN_PATCH_CHILD 1001
#define JBD_LAUNCHD_PATCH_TIMEOUT_SECONDS 10
#define POSIX_SPAWN_PROC_TYPE_DRIVER 9
#define POSIX_SPAWN_START_SUSPENDED 128
enum {XPC_TYPE_DICTIONARY=1,XPC_TYPE_INT64=2,XPC_TYPE_BOOL=3,XPC_TYPE_ERROR=4};
struct Object {int type;};
typedef struct Object *xpc_object_t;
static struct Object message={XPC_TYPE_DICTIONARY}, reply={XPC_TYPE_DICTIONARY};
static struct Object result_value={XPC_TYPE_INT64}, ack_value={XPC_TYPE_BOOL};
static int mode, resumes, kills, version_queries, server_resumed, worker_inflight;
static int releases;
static xpc_object_t xpc_dictionary_create_empty(void){return &message;}
static void xpc_dictionary_set_uint64(xpc_object_t o,const char *k,uint64_t v){(void)o;(void)k;(void)v;}
static void xpc_dictionary_set_int64(xpc_object_t o,const char *k,int64_t v){(void)o;(void)k;(void)v;}
static void xpc_dictionary_set_bool(xpc_object_t o,const char *k,bool v){(void)o;(void)k;(void)v;}
static int xpc_get_type(xpc_object_t o){return o->type;}
static xpc_object_t xpc_dictionary_get_value(xpc_object_t o,const char *k){
    (void)o;
    if(!strcmp(k,"result"))return mode==3?NULL:&result_value;
    return mode==4?NULL:&ack_value;
}
static int64_t xpc_dictionary_get_int64(xpc_object_t o,const char *k){(void)o;(void)k;return mode==1?47:0;}
static bool xpc_dictionary_get_bool(xpc_object_t o,const char *k){(void)o;(void)k;return true;}
static void xpc_release(xpc_object_t o){(void)o;releases++;}
static int test_getpid(void){return 1;}
static int proc_get_pidversion(pid_t pid){
    (void)pid;version_queries++;
    if((mode==8 || mode==9) && version_queries>=3)return mode==8?2:0;
    return 1;
}
static int test_clock_gettime(int c,struct timespec *t){(void)c;t->tv_sec=100;t->tv_nsec=0;return 0;}
static xpc_object_t jbdLaunchdBoundedSpawnPatchRequest(xpc_object_t o){
    (void)o;
    if(mode==2 || mode==6 || mode==8 || mode==9 || mode==10){worker_inflight=1;return NULL;}
    if(mode==7){server_resumed=1;return NULL;}
    if(mode==11)return NULL; /* explicit unsent injection; same NULL representation */
    reply.type=mode==5?XPC_TYPE_ERROR:XPC_TYPE_DICTIONARY;return &reply;
}
#define getpid test_getpid
#define clock_gettime test_clock_gettime
#define roothide_stage_log(...) ((void)0)
#define JBLogError(...) ((void)0)
'''

CALLER_PREFIX = r'''
static int jbdSpawnPatchChildDeferred(int pid,bool resume){return jbdSpawnPatchChildExInternal(pid,resume,false,true);}
struct Attr {short flags;int proctype;};
typedef struct Attr *posix_spawnattr_t;
struct _posix_spawn_args_desc {struct Attr attrp;};
static int posix_spawnattr_getflags(posix_spawnattr_t a,short *v){*v=a->flags;return 0;}
static int posix_spawnattr_getprocesstype_np(posix_spawnattr_t a,int *v){*v=a->proctype;return 0;}
static int posix_spawnattr_setflags(posix_spawnattr_t a,short v){a->flags=v;return 0;}
static char **envbuf_mutcopy(const char **e){(void)e;return NULL;}
static const char *envbuf_getenv(char **e,const char *k){(void)e;(void)k;return NULL;}
static void envbuf_setenv(char ***e,const char *k,const char *v){(void)e;(void)k;(void)v;}
static void envbuf_free(char **e){(void)e;}
static int __posix_spawn_orig_wrapper(pid_t *p,const char *path,struct _posix_spawn_args_desc *d,char *const a[],char *const e[]){
    (void)path;(void)a;(void)e;
    if(!(d->attrp.flags & POSIX_SPAWN_START_SUSPENDED)){fputs("not suspended\n",stderr);exit(4);}
    *p=42;return 0;
}
static int test_kill(pid_t p,int sig){
    if(p!=42){fputs("wrong target\n",stderr);exit(4);}
    if(sig==SIGCONT)resumes++;else if(sig==SIGQUIT || sig==SIGKILL)kills++;
    else {fputs("wrong signal\n",stderr);exit(4);}return 0;
}
#define kill test_kill
'''

CASES = r'''
int main(int argc,char **argv){
    if(argc!=2)return 4;mode=atoi(argv[1]);
    struct _posix_spawn_args_desc d={0};pid_t child=0;
    int result=roothide_launchd___posix_spawn_posthook(&child,"/fixture/child",&d,NULL,NULL);
    bool unknown=mode==2 || mode==3 || mode==4 || mode==5 || mode==6 || mode==7 || mode==10;
    bool unknown_kill=unknown && kills;
    /* No post-return supervisor/reaper exists in this extracted call chain. */
    bool unowned_unknown=unknown && !kills && !resumes && !server_resumed;
    printf("{\"mode\":%d,\"caller_result\":%d,\"resumes\":%d,\"termination_signals\":%d,"
           "\"worker_inflight\":%d,\"server_resumed\":%d,\"unknown_kill\":%s,\"unowned_unknown\":%s,\"releases\":%d}\n",
           mode,result,resumes,kills,worker_inflight,server_resumed,
           unknown_kill?"true":"false",unowned_unknown?"true":"false",releases);
    if(unknown_kill || unowned_unknown)return 1;
    if(mode==0 && (result || resumes!=1 || kills))return 2;
    if(mode==1 && (result!=202 || resumes || kills!=2))return 2;
    if((mode==8 || mode==9) && (resumes || kills))return 2;
    if(mode==11 && (result!=202 || kills!=2))return 2;
    return 0;
}
'''

MODES = {0: 'confirmed-success', 1: 'confirmed-failure', 2: 'no-reply-unknown',
         3: 'missing-result', 4: 'legacy-missing-ack', 5: 'invalid-reply',
         6: 'timeout-worker-still-active', 7: 'lost-reply-after-legacy-resume',
         8: 'target-identity-changed', 9: 'target-exited', 10: 'service-lost-unknown',
         11: 'request-not-sent'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--demonstrate-bad-fix', action='store_true',
                        help='Test the rejected idea of changing all unknown defaults to -2')
    args = parser.parse_args()
    client = extract((ROOT / 'BaseBin/libjailbreak/src/roothider/jailbreakd.c').read_text(encoding='utf-8'),
                     'static int jbdSpawnPatchChildExInternal(')
    caller = extract((ROOT / 'BaseBin/launchdhook/src/roothider.m').read_text(encoding='utf-8'),
                     'int roothide_launchd___posix_spawn_posthook(')
    if args.demonstrate_bad_fix:
        assert 'int64_t result = -1;' in client
        client = client.replace('int64_t result = -1;', 'int64_t result = -2;')
    folder = args.workdir.resolve()
    source = folder / 'f1_contract.c'
    program = folder / ('f1_contract.exe' if sys.platform == 'win32' else 'f1_contract')
    source.write_text(PREFIX + client + CALLER_PREFIX + caller + CASES, encoding='utf-8')
    cc = [str(args.zig.resolve()), 'cc'] if args.zig else ['cc']
    subprocess.run(cc + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(program)], check=True)
    results = []
    for mode, name in MODES.items():
        result = subprocess.run([str(program), str(mode)], capture_output=True, text=True, timeout=5)
        entry = dict(name=name, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        entry['observation'] = json.loads(result.stdout)
        results.append(entry)
        print(f'{name}: {"CONTRACT_VIOLATION" if result.returncode else "PASS"} {result.stdout.strip()}')
    unsafe = sum(item['exit_code'] != 0 for item in results)
    document = dict(provenance='independently rebuilt',
                    intentionally_broken_candidate=args.demonstrate_bad_fix,
                    limits='Injected transport outcomes; no live worker, XPC, persistent owner, atomic process signal or iOS execution.',
                    acceptance_pass=unsafe == 0, violations=unsafe, cases=results)
    args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'F1 acceptance: {"FAIL" if unsafe else "PASS"}; violations={unsafe}; bad_fix={args.demonstrate_bad_fix}')
    return 1 if unsafe else 0


if __name__ == '__main__':
    sys.exit(main())
