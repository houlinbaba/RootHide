#!/usr/bin/env python3
"""Independent error-5 provenance probe using production read/get-root/client code.

Inert kernel reads and credential installation are injected. A passing result
proves forwarding contracts only, never which failure occurred on the device.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from test_unrestrict_contract import extract

ROOT = Path(__file__).resolve().parents[2]
PREFIX = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include "credential_types.h"
#include "credential_diagnostics.h"
static void roothide_stage_file_log(const char *path,const char *format,...){(void)path;(void)format;}
#define ROOTHIDE_BOOTSTRAP_STAGE_LOG_PATH "/fixture/private.log"
#define PROC_PIDPATHINFO_MAXSIZE 1024
#define __builtin_available(...) 1
#define koffsetof(type,field) off_##field
enum {off_uid=0,off_ruid=4,off_svuid=8,off_rgid=12,off_svgid=16,off_groups=32,
      off_proc_ro=64,off_task_tokens=80,off_audit_token=8};
struct {struct {struct {bool exists;} proc_ro;} kernelStruct;} gSystemInfo;
typedef int audit_token_t;
static int mode, reads, set_calls, server_result, read_failure;
static int audit_token_to_pid(audit_token_t token){return token;}
static uint64_t proc_find(int pid){return pid==42 && mode!=1?0x100:0;}
static uint64_t proc_ucred(uint64_t proc){return proc?0x1000:0;}
static uint64_t kread_ptr(uint64_t a){return a;}
static uint32_t kread32(uint64_t a){(void)a;return 501;}
static int kwrite32(uint64_t a,uint32_t v){(void)a;(void)v;return 0;}
static int kreadbuf(uint64_t a,void *out,size_t size){
    reads++;
    if(read_failure==reads)return -37;
    uint32_t value=(a==0x1000+28)?1:((mode==2 && a==0x1000)?0:501);
    if(size!=((a==0x1000+28)?sizeof(uint16_t):sizeof(value))){fputs("invalid read size\n",stderr);exit(4);}
    memcpy(out,&value,size);return 0;
}
static int proc_pidpath_audittoken(audit_token_t *t,char *path,unsigned size){
    (void)t;if(mode==3)return 0;snprintf(path,size,"/Dopamine.app/Dopamine");return 22;
}
static int proc_credential_set(uint64_t proc,const char *path,const struct rh_credential *identity){
    (void)proc;(void)path;
    if(identity->uid || identity->gid || identity->groups[0]){fputs("invalid requested identity\n",stderr);exit(4);}
    set_calls++;
    return mode==4?EIO:mode==5?EACCES:mode==6?47:0;
}
'''
CLIENT_PREFIX = r'''
typedef void *xpc_object_t;
#define JBS_DOMAIN_DOPAMINE 5
#define JBS_DOPAMINE_GET_ROOT 2
static xpc_object_t jbserver_xpc_send(unsigned domain,unsigned action,xpc_object_t args){
    (void)args;
    if(domain!=5 || action!=2){fputs("wrong endpoint\n",stderr);exit(4);}
    audit_token_t token=42;server_result=dopamine_get_root(&token);return &server_result;
}
static int64_t xpc_dictionary_get_int64(xpc_object_t reply,const char *key){(void)key;return *(int*)reply;}
static void xpc_release(xpc_object_t reply){(void)reply;}
'''
CASES = r'''
int main(int argc,char **argv){
    if(argc!=3)return 4;mode=atoi(argv[1]);read_failure=atoi(argv[2]);
    int result=jbclient_dopamine_get_root();
    int expected=read_failure?EIO:mode==1?1:mode==2?EPERM:mode==3?ESRCH:mode==4?EIO:mode==5?EACCES:mode==6?47:0;
    printf("mode=%d injected_read_failure=%d read_calls=%d set_calls=%d server_result=%d client_result=%d\n",
           mode,read_failure,reads,set_calls,server_result,result);
    if(result!=expected || server_result!=expected)return 1;
    if((read_failure || mode==1 || mode==2 || mode==3) && set_calls)return 2;
    return 0;
}
'''

CHECKIN_PREFIX = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef ESTALE
#define ESTALE 70
#endif
static int mode, consumed, rpc_result;
static char *info_rootPath;
#define jbinfo(field) info_##field
static int jbclient_process_checkin(char **root,char **boot,char **extensions,bool *debug,bool *adhoc){
    (void)boot;(void)debug;(void)adhoc;
    rpc_result=mode==0?EIO:0;
    if(!rpc_result){*root=strdup("/fixture/root");*extensions=strdup("fixture-grant");}
    return rpc_result;
}
static long sandbox_extension_consume(const char *token){
    (void)token;if(mode==1){errno=EIO;return -1;}consumed++;return 1;
}
static void roothide_stage_log(const char *format,...){(void)format;}
'''
CHECKIN_CASES = r'''
int main(int argc,char **argv){
    if(argc!=2)return 4;mode=atoi(argv[1]);
    int result=jbclient_app_checkin();
    printf("checkin_mode=%d rpc_result=%d consumed=%d app_result=%d\n",mode,rpc_result,consumed,result);
    free(info_rootPath);
    if(mode<2)return result==EIO && consumed==0?0:1;
    return !result && consumed==1?0:1;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    lib = ROOT / 'BaseBin/libjailbreak/src'
    source = (lib / 'credentials.c').read_text(encoding='utf-8')
    diag = (lib / 'credential_diagnostics.c').read_text(encoding='utf-8')
    functions = '\n'.join(line for line in diag.splitlines() if not line.startswith('#include'))
    functions += extract(source, 'static int credential_read_bytes(') + extract(source, 'static int credential_read(') + extract(source, 'int proc_credential_read(')
    server = extract((ROOT / 'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c').read_text(encoding='utf-8'),
                     'int dopamine_get_root(')
    client = extract((lib / 'jbclient_xpc.c').read_text(encoding='utf-8'), 'int jbclient_dopamine_get_root(')
    folder = args.workdir.resolve()
    harness = folder / 'privilege_error.c'
    program = folder / ('privilege_error.exe' if sys.platform == 'win32' else 'privilege_error')
    harness.write_text(PREFIX + functions + server + CLIENT_PREFIX + client + CASES, encoding='utf-8')
    cc = [str(args.zig.resolve()), 'cc'] if args.zig else ['cc']
    subprocess.run(cc + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(lib), str(harness), '-o', str(program)], check=True)
    cases = []
    for mode, read_failure in [(m, 0) for m in range(7)] + [(0, n) for n in range(1, 9)]:
        result = subprocess.run([str(program), str(mode), str(read_failure)], capture_output=True, text=True, timeout=5)
        cases.append(dict(mode=mode, read_failure=read_failure, exit_code=result.returncode,
                          stdout=result.stdout, stderr=result.stderr))
        print(('PASS ' if result.returncode == 0 else 'FAIL ') + result.stdout.strip())
    checkin = extract((lib / 'app_checkin.c').read_text(encoding='utf-8'), 'int jbclient_app_checkin(')
    harness = folder / 'app_checkin_error.c'
    program = folder / ('app_checkin_error.exe' if sys.platform == 'win32' else 'app_checkin_error')
    harness.write_text(CHECKIN_PREFIX + checkin + CHECKIN_CASES, encoding='utf-8')
    subprocess.run(cc + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', str(harness), '-o', str(program)], check=True)
    for mode in range(3):
        result = subprocess.run([str(program), str(mode)], capture_output=True, text=True, timeout=5)
        cases.append(dict(checkin_mode=mode, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
        print(('PASS ' if result.returncode == 0 else 'FAIL ') + result.stdout.strip())
    passed = all(case['exit_code'] == 0 for case in cases)
    args.output.write_text(json.dumps(dict(provenance='independently rebuilt', acceptance_pass=passed,
        device_cause_identified=False, cases=cases), ensure_ascii=False, indent=2), encoding='utf-8')
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
