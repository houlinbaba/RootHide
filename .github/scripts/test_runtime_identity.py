#!/usr/bin/env python3
"""Execute production dispatch/parser plus mapped image and query lifecycle checks.

Windows: deterministic XPC/Mach-O substitutes only. macOS: additionally executes
the resolver against real ordinary-process dylibs and the App's async gate.
No device, kernel, privilege or restart operations.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from test_privilege_first_failure import extract, noincludes

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / 'BaseBin/libjailbreak/src'
UUID_A = '11111111-2222-3333-4444-555555555555'
UUID_B = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'

FAKE_UUID = r'''
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
typedef unsigned char uuid_t[16];
static int uuid_parse(const char *s,uuid_t out){
 if(!s || strlen(s)!=36)return -1;unsigned k=0;
 for(unsigned i=0;i<36;){if(i==8||i==13||i==18||i==23){if(s[i++]!='-')return -1;continue;}
 unsigned v;if(sscanf(s+i,"%2x",&v)!=1)return -1;out[k++]=(unsigned char)v;i+=2;}return 0;
}
static int uuid_is_null(const uuid_t u){for(int i=0;i<16;i++)if(u[i])return 0;return 1;}
static int uuid_compare(const uuid_t a,const uuid_t b){return memcmp(a,b,16);}
static void uuid_unparse_upper(const uuid_t u,char *s){
 for(unsigned i=0,k=0;i<16;i++){if(i==4||i==6||i==8||i==10)s[k++]='-';sprintf(s+k,"%02X",u[i]);k+=2;}s[36]=0;
}
'''

XPC = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "runtime_identity.h"
#include "uuid/uuid.h"
typedef int audit_token_t;
typedef enum {XPC_TYPE_DICTIONARY,XPC_TYPE_UINT64,XPC_TYPE_INT64,XPC_TYPE_BOOL,XPC_TYPE_STRING,XPC_TYPE_DATA,XPC_TYPE_ARRAY,XPC_TYPE_FD,XPC_TYPE_XPC_GENERIC} xpc_type_t;
typedef struct object *xpc_object_t;
struct object{ xpc_type_t type;int refs;int64_t number;char *string;const char *keys[16];xpc_object_t values[16];unsigned count;};
static int live,denied,forbidden,unidentified,no_reply;
static xpc_object_t captured;
static xpc_object_t obj(xpc_type_t t){xpc_object_t o=calloc(1,sizeof(*o));assert(o);o->type=t;o->refs=1;live++;return o;}
static xpc_object_t xpc_retain(xpc_object_t o){assert(o&&o->refs>0);o->refs++;return o;}
static void xpc_release(xpc_object_t o){assert(o&&o->refs>0);if(--o->refs)return;for(unsigned i=0;i<o->count;i++)xpc_release(o->values[i]);free(o->string);free(o);live--;}
static xpc_type_t xpc_get_type(xpc_object_t o){assert(o);return o->type;}
static xpc_object_t xpc_dictionary_create_empty(void){return obj(XPC_TYPE_DICTIONARY);}
static xpc_object_t xpc_dictionary_get_value(xpc_object_t o,const char *k){assert(o->type==XPC_TYPE_DICTIONARY);for(unsigned i=0;i<o->count;i++)if(!strcmp(o->keys[i],k))return o->values[i];return NULL;}
static void xpc_dictionary_set_value(xpc_object_t o,const char *k,xpc_object_t v){
 assert(o->type==XPC_TYPE_DICTIONARY);unsigned i;for(i=0;i<o->count;i++)if(!strcmp(o->keys[i],k))break;
 if(!v){if(i<o->count){xpc_release(o->values[i]);o->count--;o->keys[i]=o->keys[o->count];o->values[i]=o->values[o->count];}return;}
 if(i==o->count){assert(i<16);o->count++;o->keys[i]=k;}else xpc_release(o->values[i]);o->values[i]=xpc_retain(v);
}
static void number(xpc_object_t o,const char*k,int64_t v,xpc_type_t t){xpc_object_t n=obj(t);n->number=v;xpc_dictionary_set_value(o,k,n);xpc_release(n);}
static void xpc_dictionary_set_int64(xpc_object_t o,const char*k,int64_t n){number(o,k,n,XPC_TYPE_INT64);}
static void xpc_dictionary_set_uint64(xpc_object_t o,const char*k,uint64_t n){number(o,k,(int64_t)n,XPC_TYPE_UINT64);}
static void xpc_dictionary_set_bool(xpc_object_t o,const char*k,bool n){number(o,k,n,XPC_TYPE_BOOL);}
static void xpc_dictionary_set_string(xpc_object_t o,const char*k,const char*s){xpc_object_t n=obj(XPC_TYPE_STRING);n->string=strdup(s);xpc_dictionary_set_value(o,k,n);xpc_release(n);}
static int64_t xpc_int64_get_value(xpc_object_t o){assert(o->type==XPC_TYPE_INT64);return o->number;}
static uint64_t xpc_uint64_get_value(xpc_object_t o){assert(o->type==XPC_TYPE_UINT64);return o->number;}
static bool xpc_bool_get_value(xpc_object_t o){assert(o->type==XPC_TYPE_BOOL);return o->number;}
static const char*xpc_string_get_string_ptr(xpc_object_t o){assert(o->type==XPC_TYPE_STRING);return o->string;}
static uint64_t xpc_dictionary_get_uint64(xpc_object_t o,const char*k){xpc_object_t n=xpc_dictionary_get_value(o,k);return n&&n->type==XPC_TYPE_UINT64?(uint64_t)n->number:0;}
static int64_t xpc_dictionary_get_int64(xpc_object_t o,const char*k){xpc_object_t n=xpc_dictionary_get_value(o,k);return n&&n->type==XPC_TYPE_INT64?n->number:0;}
static bool xpc_dictionary_get_bool(xpc_object_t o,const char*k){xpc_object_t n=xpc_dictionary_get_value(o,k);return n&&n->type==XPC_TYPE_BOOL?n->number:false;}
static const char*xpc_dictionary_get_string(xpc_object_t o,const char*k){xpc_object_t n=xpc_dictionary_get_value(o,k);return n&&n->type==XPC_TYPE_STRING?n->string:NULL;}
static const void*xpc_dictionary_get_data(xpc_object_t o,const char*k,size_t*n){(void)o;(void)k;*n=0;return NULL;}
static xpc_object_t xpc_dictionary_get_array(xpc_object_t o,const char*k){return xpc_dictionary_get_value(o,k);}
static xpc_object_t xpc_dictionary_get_dictionary(xpc_object_t o,const char*k){return xpc_dictionary_get_value(o,k);}
static int xpc_dictionary_dup_fd(xpc_object_t o,const char*k){(void)o;(void)k;return -1;}
static void xpc_dictionary_set_fd(xpc_object_t o,const char*k,int n){number(o,k,n,XPC_TYPE_FD);}
static void xpc_dictionary_set_data(xpc_object_t o,const char*k,const void*p,size_t n){(void)o;(void)k;(void)p;(void)n;abort();}
static int close(int fd){(void)fd;abort();}
static void xpc_dictionary_get_audit_token(xpc_object_t o,audit_token_t*t){(void)o;*t=42;}
static xpc_object_t xpc_dictionary_create_reply(xpc_object_t o){(void)o;return xpc_dictionary_create_empty();}
static void xpc_pipe_routine_reply(xpc_object_t o){assert(!captured);captured=xpc_retain(o);}
static void roothide_handle_xpc_msg(xpc_object_t o){(void)o;}
#define JBROOT_PATH(x) x
#define JBS_DOMAIN_DOPAMINE 5
#define JBS_DOPAMINE_IS_JAILBROKEN 1
static char*read_file_to_string(const char *p){assert(!strcmp(p,"/basebin/.version"));return strdup("legacy-version");}
static bool dopamine_domain_allowed(audit_token_t t){assert(t==42);return !denied;}
static int dopamine_get_root(audit_token_t*t){(void)t;forbidden++;abort();}
static int dopamine_drop_root(audit_token_t*t){(void)t;forbidden++;abort();}
// This identity-only harness keeps the complete production action table.
// Diagnostic FD behavior is exercised by test_terminal_diagnostics; reaching
// that unrelated handler here must fail just like reaching get/drop-root.
static int dopamine_diagnostic_log_fd(uint64_t selector,int *out){(void)selector;(void)out;forbidden++;abort();}
// Keep the restart slot in the production table without exercising restart.
static int dopamine_restart_action(const char *command,int *releaseFDOut){(void)command;(void)releaseFDOut;forbidden++;abort();}
static int proc_credential_restore_self(void*p){(void)p;forbidden++;abort();}
int dopamine_is_jailbroken(char **,xpc_object_t *);
bool rh_image_uuid_for_address(const void*p,char out[37]){
 if(unidentified)return false;
 assert(p==(const void*)dopamine_is_jailbroken || p==(const void*)proc_credential_restore_self);
 strcpy(out,p==(const void*)dopamine_is_jailbroken?"11111111-2222-3333-4444-555555555555":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");return true;
}
'''

TRANSPORT = r'''
static xpc_object_t jbserver_xpc_send(uint64_t d,uint64_t a,xpc_object_t args){
 assert(d==JBS_DOMAIN_DOPAMINE && a==1 && !args);
 if(no_reply)return NULL;
 struct jbserver_domain *domains[]={NULL,NULL,NULL,NULL,&gDopamineDomain};struct jbserver_impl server={5,domains};
 xpc_object_t msg=xpc_dictionary_create_empty();xpc_dictionary_set_uint64(msg,"jb-domain",d);xpc_dictionary_set_uint64(msg,"action",a);
 int r=jbserver_received_xpc_message(&server,msg);xpc_release(msg);
 if(denied)assert(r==-2 && !captured);else assert(!r && captured);
 xpc_object_t result=captured;captured=NULL;return result;
}
// Model the old wire result=1 with the dispatcher's int ABI on this host.
static int old_status(char **v){*v=strdup("legacy-version");return 1;}
'''

CASES = r'''
static bool unchanged(struct rh_runtime_identity a,struct rh_runtime_identity b){
 return a.first_load==b.first_load && !strcmp(a.handler_uuid,b.handler_uuid) && !strcmp(a.credential_uuid,b.credential_uuid);
}
int main(void){
 assert(gDopamineDomain.actions[3].handler==(void*)dopamine_diagnostic_log_fd);
 assert(gDopamineDomain.actions[4].handler==(void*)dopamine_restart_action);
 assert(!gDopamineDomain.actions[5].handler);
 struct rh_runtime_identity value={0},sentinel={0};sentinel.first_load=true;strcpy(sentinel.handler_uuid,"unchanged");
 assert(jbclient_dopamine_runtime_identity(&value)==RH_RUNTIME_MALFORMED); // phase not yet published
 dopamine_runtime_identity_set_first_load(true);
 assert(jbclient_dopamine_is_jailbroken()); // old client, new real dispatcher/table
 assert(jbclient_dopamine_runtime_identity(&value)==RH_RUNTIME_REPORTED && value.first_load);
 assert(rh_runtime_identity_matches(&value,"11111111-2222-3333-4444-555555555555","AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"));
 assert(!rh_runtime_identity_matches(&value,"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",value.credential_uuid));
 assert(!rh_runtime_identity_matches(&value,value.handler_uuid,value.handler_uuid));
 assert(!rh_runtime_identity_matches(NULL,value.handler_uuid,value.credential_uuid));
 dopamine_runtime_identity_set_first_load(false);assert(jbclient_dopamine_runtime_identity(&value)==RH_RUNTIME_REPORTED && !value.first_load);
 xpc_object_t reply=jbserver_xpc_send(5,1,NULL);assert(!strcmp(xpc_dictionary_get_string(reply,"version"),"legacy-version") && xpc_dictionary_get_int64(reply,"result")==1);xpc_release(reply);
 jbserver_arg saved=gDopamineDomain.actions[0].args[1];void*handler=gDopamineDomain.actions[0].handler;
 gDopamineDomain.actions[0].args[1]=(jbserver_arg){0};gDopamineDomain.actions[0].handler=old_status;
 value=sentinel;assert(jbclient_dopamine_is_jailbroken());
 enum rh_runtime_identity_status old_result=jbclient_dopamine_runtime_identity(&value);
 if(old_result!=RH_RUNTIME_UNSUPPORTED)fprintf(stderr,"old-service status=%d\n",old_result);
 assert(old_result==RH_RUNTIME_UNSUPPORTED && unchanged(value,sentinel));
 gDopamineDomain.actions[0].args[1]=saved;gDopamineDomain.actions[0].handler=handler;
 unidentified=1;value=sentinel;assert(jbclient_dopamine_runtime_identity(&value)==RH_RUNTIME_UNKNOWN_IMAGE && unchanged(value,sentinel));unidentified=0;
 denied=1;assert(!jbclient_dopamine_is_jailbroken());assert(jbclient_dopamine_runtime_identity(&value)==RH_RUNTIME_NO_REPLY);denied=0;
 no_reply=1;assert(jbclient_dopamine_runtime_identity(&value)==RH_RUNTIME_NO_REPLY);no_reply=0;
 const char*keys[]={"format","first-load","handler-uuid","credential-uuid"};
 for(unsigned i=0;i<4;i++){
  reply=jbserver_xpc_send(5,1,NULL);xpc_object_t meta=xpc_dictionary_get_value(reply,"runtime-identity");
  xpc_dictionary_set_int64(meta,keys[i],0);value=sentinel;
  assert(runtime_identity_parse(reply,&value)==RH_RUNTIME_MALFORMED && unchanged(value,sentinel));xpc_release(reply);
  reply=jbserver_xpc_send(5,1,NULL);meta=xpc_dictionary_get_value(reply,"runtime-identity");
  xpc_dictionary_set_value(meta,keys[i],NULL);value=sentinel;
  assert(runtime_identity_parse(reply,&value)==(i<2?RH_RUNTIME_MALFORMED:RH_RUNTIME_UNKNOWN_IMAGE) && unchanged(value,sentinel));xpc_release(reply);
 }
 reply=jbserver_xpc_send(5,1,NULL);xpc_dictionary_set_string(reply,"runtime-identity","wrong");assert(runtime_identity_parse(reply,&value)==RH_RUNTIME_MALFORMED);xpc_release(reply);
 reply=jbserver_xpc_send(5,1,NULL);xpc_dictionary_set_value(reply,"result",NULL);assert(runtime_identity_parse(reply,&value)==RH_RUNTIME_MALFORMED);xpc_release(reply);
 reply=jbserver_xpc_send(5,1,NULL);xpc_dictionary_set_bool(reply,"result",true);assert(runtime_identity_parse(reply,&value)==RH_RUNTIME_MALFORMED);xpc_release(reply);
 reply=jbserver_xpc_send(5,1,NULL);xpc_dictionary_set_uint64(xpc_dictionary_get_value(reply,"runtime-identity"),"format",2);assert(runtime_identity_parse(reply,&value)==RH_RUNTIME_UNSUPPORTED);xpc_release(reply);
 reply=jbserver_xpc_send(5,1,NULL);xpc_dictionary_set_string(xpc_dictionary_get_value(reply,"runtime-identity"),"handler-uuid","bad");assert(runtime_identity_parse(reply,&value)==RH_RUNTIME_MALFORMED);xpc_release(reply);
 reply=jbserver_xpc_send(5,1,NULL);xpc_dictionary_set_string(xpc_dictionary_get_value(reply,"runtime-identity"),"credential-uuid","00000000-0000-0000-0000-000000000000");assert(runtime_identity_parse(reply,&value)==RH_RUNTIME_MALFORMED);xpc_release(reply);
 assert(jbclient_dopamine_runtime_identity(NULL)==RH_RUNTIME_MALFORMED);
 assert(!forbidden && !live);puts("PASS: real dispatcher/table packing, old/new compatibility, auth denial, no reply, unknown image, malformed fields, UUID mismatch, output ownership");return 0;
}
'''

IMAGE_TYPES = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "uuid/uuid.h"
#define MH_MAGIC_64 0xfeedfacf
#define LC_UUID 0x1b
#define LC_SEGMENT_64 0x19
#define VM_PROT_EXECUTE 4
struct mach_header_64{uint32_t magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved;};
struct load_command{uint32_t cmd,cmdsize;};
struct uuid_command{uint32_t cmd,cmdsize;unsigned char uuid[16];};
struct segment_command_64{uint32_t cmd,cmdsize;char name[16];uint64_t vmaddr,vmsize,fileoff,filesize;int32_t maxprot,initprot;uint32_t nsects,flags;};
typedef struct{const char*dli_fname;void*dli_fbase;const char*dli_sname;void*dli_saddr;}Dl_info;
static struct{struct mach_header_64 h;struct segment_command_64 text;struct uuid_command uuid;unsigned char code[128];} image;
static int fail_dladdr;
static int dladdr(const void*p,Dl_info*info){(void)p;if(fail_dladdr)return 0;*info=(Dl_info){.dli_fname="WRONG_DISK_FILENAME",.dli_fbase=&image};return 1;}
'''
IMAGE_CASES = r'''
int main(void){
 image.h=(struct mach_header_64){.magic=MH_MAGIC_64,.ncmds=2,.sizeofcmds=sizeof(image.text)+sizeof(image.uuid)};
 image.text=(struct segment_command_64){.cmd=LC_SEGMENT_64,.cmdsize=sizeof(image.text),.vmsize=sizeof(image),.filesize=sizeof(image),.initprot=VM_PROT_EXECUTE};
 image.uuid=(struct uuid_command){.cmd=LC_UUID,.cmdsize=sizeof(image.uuid)};assert(!uuid_parse("11111111-2222-3333-4444-555555555555",image.uuid.uuid));
 char out[37];assert(rh_image_uuid_for_address(image.code,out) && !strcmp(out,"11111111-2222-3333-4444-555555555555"));
 assert(!rh_image_uuid_for_address(NULL,out) && !out[0]);
 fail_dladdr=1;assert(!rh_image_uuid_for_address(image.code,out));fail_dladdr=0;
 assert(!rh_image_uuid_for_address(&out,out));
 image.h.magic=0;assert(!rh_image_uuid_for_address(image.code,out));image.h.magic=MH_MAGIC_64;
 image.text.cmdsize=0;assert(!rh_image_uuid_for_address(image.code,out));image.text.cmdsize=sizeof(image.text);
 image.text.initprot=0;assert(!rh_image_uuid_for_address(image.code,out));image.text.initprot=VM_PROT_EXECUTE;
 image.uuid.cmdsize=8;assert(!rh_image_uuid_for_address(image.code,out));image.uuid.cmdsize=sizeof(image.uuid);
 image.h.sizeofcmds--;assert(!rh_image_uuid_for_address(image.code,out));image.h.sizeofcmds++;
 memset(image.uuid.uuid,0,16);assert(!rh_image_uuid_for_address(image.code,out));
 puts("PASS: mapped header UUID, code membership, unsupported/malformed headers and null UUID fail closed");return 0;
}
'''

APPLE_IMAGE = r'''
#include "runtime_identity.h"
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char**argv){
 assert(argc==5);void*a=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL),*b=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);assert(a&&b);
 void*fa=dlsym(a,"fixture_code"),*fb=dlsym(b,"fixture_code");assert(fa&&fb);
 char ua[37],ub[37];assert(rh_image_uuid_for_address(fa,ua)&&rh_image_uuid_for_address(fb,ub));
 assert(!strcmp(ua,argv[3])&&!strcmp(ub,argv[4])&&strcmp(ua,ub));
 assert(!rename(argv[2],argv[1])); // disk path now points to B; A is still mapped
 assert(rh_image_uuid_for_address(fa,ua)&&!strcmp(ua,argv[3]));
 char *heap=malloc(32);assert(!rh_image_uuid_for_address(heap,ub));free(heap);
 printf("PASS: real macOS mapped A=%s survives disk replacement, distinct mapped B=%s\n",ua,argv[4]);
 dlclose(b);dlclose(a);return 0;
}
'''

APPLE_ASYNC = r'''
#import "DORuntimeIdentityQuery.h"
#include <assert.h>
static dispatch_semaphore_t releaseWorker;
static int callbacks;
static BOOL timeoutSeen;
static void pump(double seconds){NSDate*end=[NSDate dateWithTimeIntervalSinceNow:seconds];while(end.timeIntervalSinceNow>0)[[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.005]];}
int main(void){@autoreleasepool{
 releaseWorker=dispatch_semaphore_create(0);
 enum rh_runtime_identity_status (^blocked)(struct rh_runtime_identity*)=^enum rh_runtime_identity_status(struct rh_runtime_identity*out){(void)out;dispatch_semaphore_signal(releaseWorker);return RH_RUNTIME_REPORTED;};
 // First query returns before timeout; timeout callback must not fire later.
 assert(DORuntimeIdentityQueryStart(0.1,blocked,^(BOOL t,enum rh_runtime_identity_status s,struct rh_runtime_identity v){(void)v;assert(!t&&s==RH_RUNTIME_REPORTED);callbacks++;}));
 pump(0.2);assert(callbacks==1);
 // Hold actual worker beyond deadline; UI callback fires once, gate stays busy.
 dispatch_semaphore_t wait=dispatch_semaphore_create(0);
 __weak NSObject *weakOwner;@autoreleasepool{NSObject*owner=[NSObject new];weakOwner=owner;
 __weak NSObject *weakUI=owner;
 assert(DORuntimeIdentityQueryStart(0.03,^enum rh_runtime_identity_status(struct rh_runtime_identity*out){(void)out;dispatch_semaphore_wait(wait,DISPATCH_TIME_FOREVER);return RH_RUNTIME_REPORTED;},^(BOOL t,enum rh_runtime_identity_status s,struct rh_runtime_identity v){(void)s;(void)v;(void)weakUI;assert(t);timeoutSeen=YES;callbacks++;}));}
 assert(!weakOwner);pump(0.1);assert(timeoutSeen&&callbacks==2);
 for(int i=0;i<50;i++)assert(!DORuntimeIdentityQueryStart(0.01,blocked,^(BOOL t,enum rh_runtime_identity_status s,struct rh_runtime_identity v){(void)t;(void)s;(void)v;abort();}));
 dispatch_semaphore_signal(wait);pump(0.1);assert(callbacks==2);
 assert(DORuntimeIdentityQueryStart(0.1,blocked,^(BOOL t,enum rh_runtime_identity_status s,struct rh_runtime_identity v){(void)t;(void)s;(void)v;callbacks++;}));pump(0.2);assert(callbacks==3);
 puts("PASS: real Foundation/dispatch normal completion, timeout, 50 rejected repeats, weak UI release, late completion and gate reuse");return 0;}}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zig',type=Path)
    p.add_argument('--workdir',type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mutant',choices=['no-auth','accept-missing','accept-mismatch','ignore-membership'])
    p.add_argument('--mutations',action='store_true')
    a=p.parse_args()
    ui_source=(ROOT/'Application/Dopamine/UI/DOUIManager.m').read_text(encoding='utf-8')
    query_ui=extract(ui_source,'- (void)queryRootHideRuntimeIdentityFromView:')
    for forbidden in ['get_root', 'runAsRoot', 'runUnsandboxed', 'jbctl', 'checkin', 'reboot', 'respring']:
        assert forbidden not in query_ui, forbidden
    assert '__weak UIView *weakView' in query_ui and 'DORuntimeIdentityQueryStart(5.0' in query_ui
    home=(ROOT/'Application/Dopamine/UI/DOMainViewController.m').read_text(encoding='utf-8')
    assert 'queryRootHideRuntimeIdentityFromView:' not in home
    assert 'identifier:@"roothide-runtime-identity"' not in home
    folder=a.workdir or Path(tempfile.mkdtemp(prefix='runtime-identity-'))
    folder.mkdir(parents=True,exist_ok=True);folder=folder.resolve()
    (folder/'uuid').mkdir(exist_ok=True);(folder/'uuid/uuid.h').write_text(FAKE_UUID,encoding='utf-8')
    cc=[str(a.zig.resolve()),'cc'] if a.zig else ['xcrun','clang']
    cases=[]
    def run(name,source,extra=()):
        path=folder/(name+'.c');exe=folder/(name+('.exe' if sys.platform=='win32' else ''))
        path.write_text(source,encoding='utf-8')
        subprocess.run(cc+['-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-I',str(folder),'-I',str(LIB),str(path),'-o',str(exe)]+list(extra),check=True)
        r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=15)
        cases.append(dict(name=name,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));print(json.dumps(cases[-1]),flush=True)
        return r.returncode==0
    server=(ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c').read_text(encoding='utf-8')
    table=server[server.index('struct jbserver_domain gDopamineDomain'):]
    if a.mutant=='no-auth':table=table.replace('.permissionHandler = dopamine_domain_allowed','.permissionHandler = NULL')
    dispatcher=(LIB/'jbserver.c').read_text(encoding='utf-8')
    descriptors=(LIB/'jbserver.h').read_text(encoding='utf-8');descriptors=descriptors[descriptors.index('typedef enum'):descriptors.index('extern struct jbserver_impl')]
    client=(LIB/'jbclient_xpc.c').read_text(encoding='utf-8')
    parser=extract(client,'static enum rh_runtime_identity_status runtime_identity_parse(')
    if a.mutant=='accept-missing':parser=parser.replace('if (!meta) return RH_RUNTIME_UNSUPPORTED;','if (!meta) return RH_RUNTIME_REPORTED;')
    resolver=noincludes((LIB/'runtime_identity.c').read_text(encoding='utf-8'))
    matches=extract(resolver,'bool rh_runtime_identity_matches(')
    if a.mutant=='accept-mismatch':matches=matches.replace(' || uuid_compare(actual, expected)','')
    phase='static _Atomic int runtimeFirstLoad;\n'+extract(server,'void dopamine_runtime_identity_set_first_load(')
    main_source=(ROOT/'BaseBin/launchdhook/src/main.m').read_text(encoding='utf-8')
    assert main_source.index('dopamine_runtime_identity_set_first_load(firstLoad);') < main_source.index('initXPCHooks();')
    wire=XPC+descriptors+phase+extract(server,'int dopamine_is_jailbroken(')+table+extract(dispatcher,'static bool jbserver_xpc_value_matches_type(')+extract(dispatcher,'int jbserver_received_xpc_message(')+TRANSPORT+parser+extract(client,'enum rh_runtime_identity_status jbclient_dopamine_runtime_identity(')+extract(client,'bool jbclient_dopamine_is_jailbroken(')+matches+CASES
    passed=run('wire',wire)
    image=extract(resolver,'bool rh_image_uuid_for_address(')
    if a.mutant=='ignore-membership':image=image.replace('address < base || address - base >= text->vmsize','address == base')
    if passed:passed=run('mapped-substitute',IMAGE_TYPES+image+IMAGE_CASES)
    if passed and sys.platform=='darwin':
        # Use actual SDK UUID/dlfcn headers here, never the substitute uuid dir.
        apple=folder/'apple';apple.mkdir(exist_ok=True)
        paths=[];uuids=[]
        for n in [1,2]:
            src=apple/f'fixture{n}.c';src.write_text(f'int fixture_code(void){{return {n};}}\n')
            dylib=apple/f'fixture{n}.dylib';subprocess.run(cc+['-dynamiclib',str(src),'-o',str(dylib)],check=True)
            paths.append(str(dylib));uuids.append(subprocess.check_output(['dwarfdump','--uuid',str(dylib)],text=True).split()[1])
        src=apple/'image.c';src.write_text(APPLE_IMAGE);exe=apple/'image'
        subprocess.run(cc+['-std=gnu11','-Wall','-Wextra','-Werror','-I',str(LIB),str(src),str(LIB/'runtime_identity.c'),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)]+paths+uuids,capture_output=True,text=True,timeout=15)
        cases.append(dict(name='actual-macOS-images',exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));print(json.dumps(cases[-1]),flush=True);passed=r.returncode==0
        ui=ROOT/'Application/Dopamine/UI';include=apple/'libjailbreak';include.mkdir(exist_ok=True)
        (include/'runtime_identity.h').write_bytes((LIB/'runtime_identity.h').read_bytes())
        src=apple/'query.m';src.write_text(APPLE_ASYNC);exe=apple/'query'
        subprocess.run(cc+['-fobjc-arc','-fblocks','-Wall','-Wextra','-Werror','-Wno-unused-variable','-framework','Foundation','-I',str(apple),'-I',str(ui),str(src),'-o',str(exe)],check=True)
        r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=15)
        cases.append(dict(name='actual-macOS-async',exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));print(json.dumps(cases[-1]),flush=True);passed=passed and r.returncode==0
    rejected=[]
    if passed and a.mutations:
        for mutant in ['no-auth','accept-missing','accept-mismatch','ignore-membership']:
            sub=folder/mutant
            command=[sys.executable,__file__,'--workdir',str(sub),'--output',str(sub/'result.json'),'--mutant',mutant]
            if a.zig:command+=['--zig',str(a.zig.resolve())]
            r=subprocess.run(command,capture_output=True,text=True,timeout=30)
            observed=json.loads((sub/'result.json').read_text())
            assert r.returncode==1 and not observed['pass'] and any(c['exit_code'] for c in observed['cases']),(mutant,r.stderr)
            rejected.append(dict(mutant=mutant,results=observed));print('REJECTED: '+mutant,flush=True)
    a.output.write_text(json.dumps(dict(evidence_level='ordinary macOS process plus substitutes' if sys.platform=='darwin' else 'host substitutes only',device=False,**{'pass':passed},cases=cases,rejected_mutations=rejected),indent=2),encoding='utf-8')
    return 0 if passed else 1

if __name__=='__main__':sys.exit(main())
