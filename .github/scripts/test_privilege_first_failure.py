#!/usr/bin/env python3
"""Independently rebuilt D1 observability gate; no live privilege operations.

Runs production credential/get-root code, full check-in server handler, and
full check-in client/App flow. Host substitutes do not identify device error 5.
"""
import argparse
import json
import re
from pathlib import Path
import subprocess
import sys
import test_roothide_credentials as model

ROOT=Path(__file__).resolve().parents[2]
LIB=ROOT/'BaseBin/libjailbreak/src'

def extract(source,signature):
    # Brace counting must ignore commented-out alternative check-in bodies.
    masked=re.sub(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m:' '*len(m.group()),source)
    start=source.index(signature);opening=masked.index('{',start);depth=0
    for pos in range(opening,len(masked)):
        depth+=(masked[pos]=='{')-(masked[pos]=='}')
        if not depth:return source[start:pos+1]
    raise ValueError(signature)

ROOT_CASES=r'''
static void require_log(const char *boundary,const char *origin,const char *domain,int raw,int converted){
    assert(failure_log_count==1);
    char value[64];snprintf(value,sizeof(value),"raw=%d ",raw);assert(strstr(failure_log,value));
    snprintf(value,sizeof(value),"converted=%d ",converted);assert(strstr(failure_log,value));
    assert(strstr(failure_log,boundary) && strstr(failure_log,origin) && strstr(failure_log,domain));
    assert(!strstr(failure_log,"0x") && !strstr(failure_log,"/Applications") && !strstr(failure_log,"501"));
    puts(failure_log);
}
static void init_case(void){reset();runtime_server=true;read_calls=fail_read=fail_path=missing_target=0;}
int main(void){
    audit_token_t token=100;
    init_case();assert(!dopamine_get_root(&token) && !failure_log_count);assert_immutable();
    init_case();missing_target=1;assert(dopamine_get_root(&token)==1 && !spawn_calls);
    require_log("boundary=find_target","origin=find_target","domain=lookup_bool",0,1);
    for(int i=1;i<=8;i++){
        init_case();fail_read=i;errno=EBADF;assert(dopamine_get_root(&token)==EIO && !spawn_calls && errno==EBADF);
        require_log("boundary=pre_read","origin=credential_read.","domain=kernel_io_return",-37,EIO);
    }
    init_case();fail_path=1;assert(dopamine_get_root(&token)==ESRCH && !spawn_calls && errno==EACCES);
    require_log("boundary=target_path","origin=target_path","domain=libproc_return",0,ESRCH);
    init_case();store_identity(old_cred,&root);assert(dopamine_get_root(&token)==EPERM && !spawn_calls);
    require_log("boundary=validate_identity","origin=validate_identity","domain=policy_status",EPERM,EPERM);
    init_case();fail_spawn=ENOENT;assert(dopamine_get_root(&token)==ENOENT);assert_rolled_back();
    require_log("boundary=install","origin=spawn","domain=posix_status",ENOENT,ENOENT);
    init_case();ready_mode=1;assert(dopamine_get_root(&token)==ETIMEDOUT);assert_rolled_back();
    require_log("boundary=install","origin=helper_ready","domain=timeout_status",ETIMEDOUT,ETIMEDOUT);
    init_case();fail_resume=EPERM;assert(dopamine_get_root(&token)==EPERM);assert_rolled_back();
    require_log("boundary=install","origin=resume_helper","domain=posix_errno",EPERM,EPERM);
    init_case();fail_map_at=1;assert(dopamine_get_root(&token)==EIO);assert_rolled_back();
    require_log("boundary=install","origin=credential_ref.map","domain=physaccess_return",-47,EIO);
    init_case();fail_write_at=1;assert(dopamine_get_root(&token)==EIO);assert_rolled_back();
    require_log("boundary=install","origin=install.write_saved_uid","domain=kernel_io_return",-83,EIO);
    init_case();published_error=1;assert(!dopamine_get_root(&token) && !failure_log_count);assert_immutable();
    init_case();fail_read=1;assert(apply_saved_ids(target,"/Applications/Dopamine.app/Dopamine")==EIO);
    require_log("boundary=app_pre_read","origin=credential_read.field","domain=kernel_io_return",-37,EIO);
    init_case();fail_spawn=ENOENT;assert(apply_saved_ids(target,"/Applications/Dopamine.app/Dopamine")==ENOENT);
    require_log("boundary=app_install","origin=spawn","domain=posix_status",ENOENT,ENOENT);
    // Logging may itself fail. Finishing must preserve caller errno and the
    // first error even when later cleanup reports another error.
    init_case();struct rh_failure_scope outer,inner;
    rh_failure_begin(&outer,"outer",100);errno=EACCES;rh_failure_note("first","raw_return",-71,EIO);
    rh_failure_note("cleanup","raw_return",-99,EPERM);
    rh_failure_begin(&inner,"inner",100);errno=EBADF;
    assert(rh_failure_end(&inner,"inner_boundary","status",EPERM,EPERM)==EPERM && errno==EBADF);
    failure_log_count=0;errno=ENOENT;
    assert(rh_failure_end(&outer,"outer_boundary","status",EIO,EIO)==EIO && errno==ENOENT);
    require_log("boundary=outer_boundary","origin=first","domain=raw_return",-71,EIO);
    // No active request after finish: no stack pointer retained for next RPC.
    rh_failure_note("orphan","status",1,1);
    struct rh_failure_scope next;rh_failure_begin(&next,"next",100);
    failure_log_count=0;assert(!rh_failure_end(&next,"ok","status",0,0) && !failure_log_count);
    puts("PASS: 20 production credential/caller diagnostic scenarios plus nested-scope, first-error and errno checks");
    return 0;
}
'''

SERVER_PREFIX=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "credential_types.h"
#include "credential_diagnostics.h"
typedef int audit_token_t;
typedef int pid_t;
#define __builtin_available(...) 1
#define MAXPATHLEN 1024
#undef PATH_MAX
#define PATH_MAX 4096
#define ROOTHIDE_BOOTSTRAP_STAGE_LOG_PATH "/fixture/private.log"
#define JBROOT_PATH(p) p
#define JBLogError(...) ((void)0)
#define CS_OPS_STATUS 0
#define CS_PLATFORM_BINARY 1
#define CS_INSTALLER 2
#define P_SUGID 4
#define SIGKILL 9
#define DISPATCH_QUEUE_PRIORITY_DEFAULT 0
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISREG(m) true
#define jbsetting(n) false
#define ksymbol(n) 0
#define koffsetof(t,f) 0
static int mode,read_calls,set_calls,platform_calls,logs;
static char message[1024];
static void roothide_stage_file_log(const char *p,const char *f,...){(void)p;va_list a;va_start(a,f);vsnprintf(message,sizeof(message),f,a);va_end(a);logs++;}
static int audit_token_to_pid(int t){return t;}
static int proc_pidpath(int p,char *out,unsigned n){(void)p;assert(n>32);if(mode==1||mode==10){errno=EACCES;return 0;}strcpy(out,"/fixture/Dopamine");return 18;}
static int proc_pidpath_audittoken(int *p,char *out,unsigned n){return proc_pidpath(*p,out,n);}
static uint64_t proc_find(int p){assert(p==42);return mode==2?0:123;}
static int systemwide_get_jbroot(char **s){if(mode==3){errno=ENOMEM;return -1;}*s=strdup("/fixture/root");return 0;}
static int systemwide_get_boot_uuid(char **s){if(mode==4){errno=ENOMEM;return -1;}*s=strdup("fixture-uuid");return 0;}
static int csops(int p,int op,void *o,size_t n){(void)p;(void)op;(void)n;*(uint32_t*)o=0;return 0;}
static bool is_dopamine_app(const char *p){(void)p;return mode!=9;}
static char *generate_sandbox_extensions(int *t,bool w){assert(*t==42&&w);return strdup("PRIVATE-GRANT-NEVER-LOG");}
static bool isRemovableBundlePath(const char *p){(void)p;return false;}
static bool isSubPathOf(const char *p,const char *r){(void)p;(void)r;return false;}
static void cs_allow_invalid(uint64_t p,bool b){(void)p;(void)b;}
struct stat{unsigned st_mode,st_uid,st_gid;};
static int stat(const char *p,struct stat *s){(void)p;*s=(struct stat){mode==7||mode==8?S_ISUID:0,0,0};return 0;}
static int proc_credential_read(uint64_t p,struct rh_credential *c){assert(p==123);read_calls++;if(mode==5||mode==7){rh_failure_note("credential_read.field","kernel_io_return",-37,EIO);return EIO;}*c=(struct rh_credential){.uid=501,.ngroups=1};return 0;}
static int proc_credential_set(uint64_t p,const char *s,const struct rh_credential *c){(void)s;(void)c;assert(p==123);set_calls++;if(mode==6||mode==8){rh_failure_note("spawn","posix_status",ENOENT,ENOENT);return ENOENT;}return 0;}
static uint64_t proc_ucred(uint64_t p){return p;}
static int kwrite32(uint64_t a,uint32_t b){(void)a;(void)b;return 0;}
static uint32_t kread32(uint64_t a){(void)a;return 0;}
static void proc_allow_all_syscalls(uint64_t p){(void)p;}
static void proc_remove_msg_filter(uint64_t p){(void)p;}
static void *dispatch_get_global_queue(int p,int f){(void)p;(void)f;return NULL;}
static void dispatch_async(void *q,void (^b)(void)){(void)q;b();}
static int killall(const char *p,int s){(void)p;(void)s;return 0;}
static void proc_csflags_set(uint64_t p,int f){(void)p;(void)f;platform_calls++;}
static void proc_rele(uint64_t p){(void)p;}
#ifdef _WIN32
void *_NSConcreteStackBlock[32], *_NSConcreteGlobalBlock[32];
#endif
'''
SERVER_CASES=r'''
int main(int argc,char **argv){
    assert(argc==2);mode=atoi(argv[1]);audit_token_t token=42;
    if(mode>=9){assert(!dopamine_domain_allowed(token));assert(logs==1 && strstr(message,mode==9?"origin=authorize_bundle":"origin=authorize_path"));puts(message);return 0;}
    char *root=NULL,*boot=NULL,*grants=NULL;bool debug=false,adhoc=false;
    int r=systemwide_process_checkin(&token,&root,&boot,&grants,&debug,&adhoc);
    int expected=mode==0?0:mode<=4?-1:mode==5||mode==7?EIO:ENOENT;
    assert(r==expected && logs==(mode!=0));
    const char *phases[]={"complete","target_path","find_target","root_metadata","boot_metadata","app_pre_read","app_install","setid_pre_read","setid_install"};
    if(mode){assert(strstr(message,phases[mode]) && !strstr(message,"PRIVATE-GRANT") && !strstr(message,"/fixture"));puts(message);assert(!platform_calls);}
    else assert(platform_calls==2 && read_calls==1 && set_calls==1);
    if(mode==5||mode==7)assert(!set_calls && strstr(message,"raw=-37") && strstr(message,"domain=kernel_io_return"));
    free(root);free(boot);free(grants);return 0;
}
'''

CLIENT_PREFIX=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#ifndef ESTALE
#define ESTALE 70
#endif
typedef void *xpc_object_t;
#define XPC_TYPE_INT64 1
#define JBS_DOMAIN_SYSTEMWIDE 1
#define JBS_SYSTEMWIDE_PROCESS_CHECKIN 1
static int mode,releases,consumes;
static char *info_rootPath;
#define jbinfo(f) info_##f
static char events[4096];
static void roothide_stage_log(const char *f,...){int e=errno;va_list a;va_start(a,f);size_t n=strlen(events);vsnprintf(events+n,sizeof(events)-n,f,a);va_end(a);strcat(events,"\n");errno=e;}
static xpc_object_t jbserver_xpc_send(int d,int a,void *p){assert(d==1&&a==1&&!p);return mode==1?NULL:(void*)1;}
static xpc_object_t xpc_dictionary_get_value(void *r,const char *k){(void)r;(void)k;return mode==2?NULL:(void*)1;}
static int xpc_get_type(void *v){(void)v;return XPC_TYPE_INT64;}
static int64_t xpc_dictionary_get_int64(void *r,const char *k){(void)r;(void)k;return mode==3?5:0;}
static const char *xpc_dictionary_get_string(void *r,const char *k){(void)r;if(!strcmp(k,"root-path"))return mode==4?NULL:"/fixture/root";if(!strcmp(k,"sandbox-extensions"))return mode==8?"SECRET-A||SECRET-B":"SECRET-A|SECRET-B";return "boot";}
static bool xpc_dictionary_get_bool(void *r,const char *k){(void)r;(void)k;return false;}
static void xpc_release(void *r){assert(r);releases++;}
static long sandbox_extension_consume(const char *s){assert(!strncmp(s,"SECRET-",7));consumes++;if((mode==6&&consumes==1)||(mode==7&&consumes==2)){errno=5;return -1;}return consumes;}
'''
CLIENT_CASES=r'''
int main(int argc,char **argv){
    assert(argc==2);mode=atoi(argv[1]);if(mode==5)info_rootPath=strdup("/different");
    int r=jbclient_app_checkin();
    int want=mode==1?-1:mode==2||mode==4||mode==8?EPROTO:mode==3||mode==6||mode==7?5:mode==5?ESTALE:0;
    assert(r==want && releases==(mode!=1));
    if(mode==1)assert(strstr(events,"phase=no_reply") && !consumes);
    if(mode==2)assert(strstr(events,"phase=reply_type") && !consumes);
    if(mode==3)assert(strstr(events,"phase=server_reply domain=server_status raw=5") && strstr(events,"rpc_result=5 consume_errno=0") && !consumes);
    if(mode==6||mode==7)assert(strstr(events,"phase=grant_consume rpc_result=0 consume_errno=5 result=5"));
    if(mode==4)assert(strstr(events,"phase=reply_fields"));
    if(mode==5)assert(strstr(events,"phase=root_match"));
    if(mode==8)assert(strstr(events,"phase=grant_format") && consumes==1);
    assert(!strstr(events,"SECRET-") && !strstr(events,"/fixture"));
    puts(events);free(info_rootPath);return 0;
}
'''

THREAD_CASE=r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "credential_diagnostics.h"
#define ROOTHIDE_BOOTSTRAP_STAGE_LOG_PATH "/fixture/private.log"
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static int arrived;
static _Thread_local int local_id,logged;
static void roothide_stage_file_log(const char *p,const char *f,...){(void)p;char buf[1024],want[64];va_list a;va_start(a,f);vsnprintf(buf,sizeof(buf),f,a);va_end(a);snprintf(want,sizeof(want),"pid=%d ",local_id);assert(strstr(buf,want));snprintf(want,sizeof(want),"raw=%d ",local_id);assert(strstr(buf,want));logged++;errno=EBUSY;}
/* DIAGNOSTICS */
static void *run(void *arg){
    local_id=(int)(long long)arg;struct rh_failure_scope scope;
    rh_failure_begin(&scope,"parallel",local_id);errno=EACCES;
    rh_failure_note("own_first","fixture_status",local_id,EIO);
    pthread_mutex_lock(&mutex);arrived++;pthread_cond_broadcast(&changed);
    while(arrived<8)pthread_cond_wait(&changed,&mutex);pthread_mutex_unlock(&mutex);
    assert(rh_failure_end(&scope,"end","status",EPERM,EPERM)==EPERM && errno==EACCES && logged==1);
    return NULL;
}
int main(void){pthread_t t[8];for(int i=0;i<8;i++)assert(!pthread_create(&t[i],NULL,run,(void*)(long long)(i+1)));for(int i=0;i<8;i++)assert(!pthread_join(t[i],NULL));puts("PASS: 8 overlapping requests keep first failure and errno per thread");return 0;}
'''

def noincludes(s):
    return '\n'.join(x for x in s.splitlines() if not x.startswith('#include'))+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zig',type=Path)
    p.add_argument('--workdir',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mutant',choices=['no-first-log','last-error-wins','clobber-errno'])
    p.add_argument('--baseline',help='Git revision for before/after diagnostic gate')
    p.add_argument('--mutations',action='store_true',help='Require 3 deliberately broken diagnostics to fail')
    a=p.parse_args();folder=a.workdir.resolve();cc=[str(a.zig.resolve()),'cc'] if a.zig else ['cc']
    def read(path):
        return subprocess.check_output(['git','-c','safe.directory='+str(ROOT),'show',a.baseline+':'+str(path.relative_to(ROOT)).replace('\\','/')],text=True,encoding='utf-8') if a.baseline else path.read_text(encoding='utf-8')
    diag=noincludes((LIB/'credential_diagnostics.c').read_text(encoding='utf-8'))
    if a.mutant=='no-first-log':diag=diag.replace('if (result) {','if (0) {')
    if a.mutant=='last-error-wins':diag=diag.replace(' || activeFailure->phase','')
    if a.mutant=='clobber-errno':diag=diag.replace('errno = savedErrno;','(void)savedErrno; errno = EBUSY;')
    # Inject raw kernel I/O statuses into existing immutable-credential model.
    prefix=model.PREFIX.replace('static int kreadbuf(', 'static int fail_read,read_calls,fail_path,missing_target;\nstatic int kreadbuf(')
    prefix=prefix.replace('assert(a+n<sizeof(kmem)); memcpy(b,kmem+a,n); return 0;', 'assert(a+n<sizeof(kmem));if(++read_calls==fail_read)return -37; memcpy(b,kmem+a,n); return 0;')
    prefix=prefix.replace('p==100 ? target','p==100 ? (missing_target?0:target)')
    prefix=prefix.replace('if (map_calls==fail_map_at || map_calls==fail_map_extra) return EIO;','if (map_calls==fail_map_at || map_calls==fail_map_extra) return -47;')
    prefix=prefix.replace('if (++writes==fail_write_at) return EIO;','if (++writes==fail_write_at) return -83;')
    # This logger deliberately corrupts errno; production finish must restore it.
    prefix=prefix.replace('failure_log_count++;return;','failure_log_count++;errno=EBUSY;return;')
    runtime=model.runtime_callers()
    if a.baseline:
        current=extract((ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c').read_text(encoding='utf-8'),'int dopamine_get_root(').replace('__builtin_available(iOS 17.0, *)','1')
        old=extract(read(ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c'),'int dopamine_get_root(').replace('__builtin_available(iOS 17.0, *)','1')
        runtime=runtime.replace(current,old)
    runtime=runtime.replace('strcpy(path, "/Applications/Dopamine.app/Dopamine");','if(fail_path){errno=EACCES;return 0;}strcpy(path, "/Applications/Dopamine.app/Dopamine");')
    suffix=model.SUFFIX.replace('int main(void)', 'static int legacy_main(void)')
    # Legacy main refers to this forward declaration; it is not run here.
    credential=prefix+diag+noincludes(read(LIB/'credentials.c'))+runtime+suffix+model.CALLER_CASES+ROOT_CASES
    server=SERVER_PREFIX+diag+extract(read(ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c'),'bool dopamine_domain_allowed(')+extract(read(ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c'),'int systemwide_process_checkin(')+SERVER_CASES
    client=CLIENT_PREFIX+extract(read(LIB/'jbclient_xpc.c'),'int jbclient_process_checkin(')+extract(read(LIB/'app_checkin.c'),'int jbclient_app_checkin(')+CLIENT_CASES
    cases=[]
    for name,source,modes in [('credentials',credential,[None]),('checkin-server',server,range(11)),('checkin-client',client,range(9)),('threads',THREAD_CASE.replace('/* DIAGNOSTICS */',diag),[None])]:
        path=folder/(name+'.c');program=folder/(name+('.exe' if sys.platform=='win32' else ''))
        path.write_text(source,encoding='utf-8')
        (folder/'sys').mkdir(exist_ok=True)
        (folder/'sys/syscall.h').write_text('\n'.join(f'#define SYS_{n} {i+1}' for i,n in enumerate(model.SYSCALLS)),encoding='utf-8')
        subprocess.run(cc+['-std=gnu11','-fblocks','-pthread','-Wall','-Wextra','-Werror','-Wno-unused-function','-I',str(folder),'-I',str(LIB),str(path),'-o',str(program)],check=True)
        for mode in modes:
            r=subprocess.run([str(program)]+([] if mode is None else [str(mode)]),capture_output=True,text=True,timeout=10)
            case=dict(component=name,mode=mode,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr);cases.append(case)
            print(json.dumps(case,ensure_ascii=False),flush=True)
            if r.returncode:break
        if cases[-1]['exit_code']:break
    passed=all(c['exit_code']==0 for c in cases)
    rejected=[]
    if passed and a.mutations:
        for mutation in ['no-first-log','last-error-wins','clobber-errno']:
            subdir=folder/mutation;subdir.mkdir(exist_ok=True)
            command=[sys.executable,str(Path(__file__).resolve()),'--workdir',str(subdir),'--output',str(subdir/'results.json'),'--mutant',mutation]
            if a.zig:command+=['--zig',str(a.zig.resolve())]
            r=subprocess.run(command,capture_output=True,text=True,timeout=30)
            observed=json.loads((subdir/'results.json').read_text(encoding='utf-8'))
            assert r.returncode==1 and not observed['acceptance_pass'],(mutation,r.returncode,r.stderr)
            rejected.append(dict(mutation=mutation,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
            print('REJECTED: '+mutation,flush=True)
    a.output.write_text(json.dumps(dict(provenance='independently rebuilt',acceptance_pass=passed,baseline=a.baseline,mutant=a.mutant,cases=cases,rejected_mutations=rejected),ensure_ascii=False,indent=2),encoding='utf-8')
    return 0 if passed else 1

if __name__=='__main__':sys.exit(main())
