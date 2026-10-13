#!/usr/bin/env python3
"""Exercise production dyld redirection with deterministic Mach failures.

The host model executes the real patch function for arm64/arm64e and iOS
15/16/17, including cleanup and the existing trampoline writer. It does not
validate device code signing, remapping or execution of the emitted branch.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


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
#define KERN_SUCCESS 0
#define MACH_PORT_NULL 0
#define MACH_PORT_VALID(p) ((p)!=0)
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_PROT_COPY 16
#define VM_FLAGS_ANYWHERE 1
#define VM_INHERIT_COPY 1
#define TASK_DYLD_INFO 17
#define TASK_DYLD_INFO_COUNT 5
#define ARM_THREAD_STATE64 6
#define ARM_THREAD_STATE64_COUNT 68
#define PAGE_SIZE 16384
#define JBROOT_PATH(p) p
#define proc_get_path(pid,out) "/RootHide.app/RootHide"
#define ROOTHIDE_JAILBREAKD_STAGE_LOG_PATH "/mock/stage.log"
#define getpid() 1
typedef int kern_return_t, vm_prot_t;
typedef int rh_test_pid_t;
#define pid_t rh_test_pid_t
typedef unsigned mach_port_t, task_port_t, mach_msg_type_number_t;
typedef uintptr_t vm_address_t, mach_vm_address_t, vm_offset_t;
typedef unsigned *thread_state_t;
typedef void *task_info_t;
typedef mach_port_t *thread_act_array_t;
typedef unsigned dispatch_once_t;
#ifdef _WIN32
void *_NSConcreteGlobalBlock[32];
#endif
#define dispatch_once(t,b) do { if (!(*(t))++) (b)(); } while(0)
struct mach_header_64 { uint32_t fields[8]; };
struct DYLDINFO {
    uint64_t all_image_info_addr, all_image_info_size, entrypoint, vmSpaceSize;
    uint64_t loadDyldCache_function, loadDyldCache_trampoline;
    void *imageAddress;
};
typedef struct { uint64_t all_image_info_addr; } task_dyld_info_data_t;
typedef struct { void *__opaque_pc; uintptr_t sp, fp, lr; } arm_thread_state64_t;
static int test_os=17, failure, fail_write_at, fail_protect_at, old_pac;
static int redirects, core_writes, task_ports, thread_ports, arrays;
static int remote_frees, old_frees, infos, allow_invalid, protects, writes;
static int no_entry, fake_thread_count=2;
static uint32_t emitted[5];
static struct DYLDINFO dyld={0x100,0x80,0x800,0x8000,0x1000,0x2000,(void*)0x700000};
static void log_message(const char *fmt, ...) { (void)fmt; }
#define JBLogDebug log_message
#define JBLogError log_message
#define roothide_stage_log log_message
#define roothide_stage_file_log log_message
static const char *mach_error_string(int n) { (void)n;return "mock"; }
static mach_port_t mach_task_self(void) { return 1; }
static struct DYLDINFO *loadDyldInfo(const char *p) { (void)p;return &dyld; }
static kern_return_t task_for_pid(mach_port_t self,int pid,task_port_t *p) {
    assert(self==1 && pid==969);if(failure==1)return 5;*p=42;task_ports++;return 0;
}
static kern_return_t task_info(mach_port_t p,int flavor,task_info_t data,uint32_t *count) {
    assert(p==42 && flavor==TASK_DYLD_INFO && *count==TASK_DYLD_INFO_COUNT);
    if(failure==2)return 5;((task_dyld_info_data_t*)data)->all_image_info_addr=0x100100;return 0;
}
static kern_return_t vm_remap(mach_port_t p,vm_address_t *addr,uint64_t size,
    int mask,int flags,mach_port_t self,mach_vm_address_t src,bool copy,
    vm_prot_t *cur,vm_prot_t *max,int inherit) {
    assert(p==42 && size==0x8000 && !mask && flags==1 && self==1 && src==0x700000 && copy && inherit==1);
    if(failure==3)return 5;*addr=0x400000;*cur=*max=5;return 0;
}
static uint64_t proc_find(int pid) { assert(pid==969);return failure==4?0:0x500; }
static uint64_t proc_task(uint64_t p) { assert(p==0x500);return failure==5?0:0x600; }
static bool dyld_patch_enabled(void) { return true; }
static void cs_allow_invalid(uint64_t p,bool value) { assert(p==0x500 && !value);allow_invalid++; }
static int hook_dyld_function(mach_port_t p,uint64_t old,uint64_t newp,uint64_t orig) {
    assert(p==42 && old==0x101000 && newp==0x401000 && orig==0x402000);return failure==6?-1:0;
}
static int task_set_dyld_info(uint64_t p,uint64_t addr,uint64_t size) {
    assert(p==0x600 && size==0x80 && (addr==0x400100 || addr==0x100100));infos++;return failure==12?-1:0;
}
static kern_return_t task_threads(mach_port_t p,thread_act_array_t *out,mach_msg_type_number_t *count) {
    assert(p==42);if(failure==7)return 5;*count=fake_thread_count;
    if(!fake_thread_count){*out=NULL;return 0;}
    *out=malloc(sizeof(mach_port_t)*2);assert(*out);(*out)[0]=10;(*out)[1]=11;
    thread_ports+=fake_thread_count;arrays++;return 0;
}
static kern_return_t thread_get_state(mach_port_t p,int flavor,thread_state_t state,mach_msg_type_number_t *count) {
    assert((p==10 || p==11) && flavor==ARM_THREAD_STATE64 && *count==ARM_THREAD_STATE64_COUNT);
    if(failure==8)return 5;arm_thread_state64_t *s=(void*)state;
    s->__opaque_pc=(void*)(uintptr_t)((p==11 && !no_entry)?0x100800:0x100900);s->sp=0x800000;s->fp=0x800000;s->lr=0;return 0;
}
/* Darwin's standard headers can already import these SDK helpers. The
 * deterministic thread model replaces them deliberately, after all includes. */
#undef __darwin_arm_thread_state64_ptrauth_strip
#undef __darwin_arm_thread_state64_get_pc
#undef __darwin_arm_thread_state64_get_sp
#undef __darwin_arm_thread_state64_get_fp
#undef __darwin_arm_thread_state64_get_lr
#undef __darwin_arm_thread_state64_set_pc_fptr
#undef ptrauth_key_process_independent_code
#undef ptrauth_sign_unauthenticated
#define __darwin_arm_thread_state64_ptrauth_strip(s) ((void)(s))
#define __darwin_arm_thread_state64_get_pc(s) ((s).__opaque_pc)
#define __darwin_arm_thread_state64_get_sp(s) ((s).sp)
#define __darwin_arm_thread_state64_get_fp(s) ((s).fp)
#define __darwin_arm_thread_state64_get_lr(s) ((s).lr)
#define ptrauth_key_process_independent_code 0
#define ptrauth_sign_unauthenticated(p,k,d) (p)
static void set_pc(arm_thread_state64_t *s,void *p) { s->__opaque_pc=(old_pac && p==(void*)0x100800)?(void*)0x100801:p; }
#define __darwin_arm_thread_state64_set_pc_fptr(s,p) set_pc(&(s),p)
static kern_return_t thread_set_state(mach_port_t p,int flavor,thread_state_t state,mach_msg_type_number_t count) {
    assert(test_os<17); /* This call would kill a platform caller on iOS 17. */
    assert(p==11 && flavor==ARM_THREAD_STATE64 && count==ARM_THREAD_STATE64_COUNT);
    assert(((arm_thread_state64_t*)state)->__opaque_pc==(void*)0x400800);core_writes++;return failure==10?5:0;
}
static kern_return_t vm_deallocate(mach_port_t p,mach_vm_address_t addr,uint64_t size) {
    if(p==1){assert(arrays==1 && size==sizeof(mach_port_t)*2);free((void*)addr);arrays--;return 0;}
    assert(p==42);
    if(addr==0x400000){assert(size==0x8000 || size==PAGE_SIZE);remote_frees++;return 0;}
    assert(addr==0x100000 && size==0x8000);old_frees++;return failure==11?5:0;
}
static kern_return_t mach_port_deallocate(mach_port_t self,mach_port_t p) {
    assert(self==1);if(p==42)task_ports--;else{assert(p==10 || p==11);thread_ports--;}return 0;
}
static kern_return_t vm_protect(mach_port_t p,vm_address_t addr,uint64_t size,bool maximum,int prot) {
    assert(p==42 && !maximum && (addr==0x100000 || addr==0x100800) && size>0);
    assert(prot==(VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY) || prot==(VM_PROT_READ|VM_PROT_EXECUTE));
    protects++;return protects==fail_protect_at?5:0;
}
static kern_return_t vm_write(mach_port_t p,vm_address_t addr,vm_offset_t data,uint64_t size) {
    assert(p==42);writes++;if(writes==fail_write_at)return 5;
    if(addr==0x100000){assert(size==sizeof(struct mach_header_64));struct mach_header_64 zero={0};assert(!memcmp((void*)data,&zero,size));}
    else{assert(addr==0x100800 && size==sizeof(emitted));memcpy(emitted,(void*)data,size);}
    return 0;
}
'''

CASES = r'''
static void reset(void) {
    assert(!task_ports && !thread_ports && !arrays);
    failure=fail_write_at=fail_protect_at=old_pac=0;fake_thread_count=2;no_entry=0;
    redirects=core_writes=remote_frees=old_frees=infos=allow_invalid=protects=writes=0;
    memset(emitted,0,sizeof(emitted));
}
static void cleaned(void) { assert(!task_ports && !thread_ports && !arrays); }
int main(void) {
    for(test_os=17;test_os<=18;test_os++){
        reset();assert(!proc_patch_dyld_internal(969,false));cleaned();
        assert(redirects==1 && !core_writes && !old_frees && !remote_frees && infos==1 && allow_invalid==1);
        assert(emitted[4]==0xD61F0000);
        uint64_t destination=((uint64_t)((emitted[0]>>5)&0xffff)<<48)|
            ((uint64_t)((emitted[1]>>5)&0xffff)<<32)|((uint64_t)((emitted[2]>>5)&0xffff)<<16)|((emitted[3]>>5)&0xffff);
        assert(destination==0x400800);
        for(int err=1;err<=12;err++){
            if(err==6 || err==9 || err==10 || err==11)continue;
            reset();failure=err;assert(proc_patch_dyld_internal(969,false));cleaned();assert(!core_writes);
            assert(remote_frees==(err>=4));
        }
        for(int err=1;err<=3;err++){
            reset();fail_protect_at=err;assert(proc_patch_dyld_internal(969,false));cleaned();
            assert(!core_writes && !infos && remote_frees==1);
        }
        for(int err=1;err<=2;err++){
            reset();fail_write_at=err;assert(proc_patch_dyld_internal(969,false));cleaned();
            assert(!core_writes && !infos && remote_frees==1);
        }
        reset();fake_thread_count=0;assert(proc_patch_dyld_internal(969,false));cleaned();assert(!redirects && remote_frees==1);
        reset();no_entry=1;assert(proc_patch_dyld_internal(969,false));cleaned();assert(!redirects && remote_frees==1);
    }
    for(test_os=15;test_os<=16;test_os++){
        reset();assert(!proc_patch_dyld_internal(969,false));cleaned();assert(core_writes==1 && old_frees==1 && !redirects);
        reset();failure=10;assert(proc_patch_dyld_internal(969,false));cleaned();assert(core_writes==1 && !old_frees && remote_frees==1);
#ifdef __arm64e__
        reset();old_pac=1;assert(!proc_patch_dyld_internal(969,false));cleaned();assert(redirects==1 && !core_writes && !old_frees);
        if(test_os==15){reset();assert(!proc_patch_dyld_internal(969,true));cleaned();assert(!core_writes && !redirects && remote_frees==1);}
#endif
    }
    puts("PASS: production iOS 17 dyld trampoline avoids core state writes; Mach failures clean ports, arrays and mappings; iOS 15/16 routes preserved");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    source = (ROOT / 'BaseBin/libjailbreak/src/roothider/dyld_patch.m').read_text(encoding='utf-8')
    assert '#include "../roothide_stage.h"' in source
    production_patch = extract(source, 'int proc_patch_dyld_internal(')
    assert production_patch.index('__builtin_available(iOS 17.0') < production_patch.index('thread_set_state(')
    # Only availability is simulated; all production branch/cleanup code runs.
    patch = re.sub(r'__builtin_available\(iOS (\d+)\.0, \*\)', r'(test_os >= \1)', production_patch)
    hook = extract(source, 'int hook_dyld_entry(')
    wrapper = r'''
static int test_hook_dyld_entry(mach_port_t task,uint64_t header,uint64_t entry,uint64_t destination) {
    redirects++;return hook_dyld_entry(task,header,entry,destination);
}
#define hook_dyld_entry test_hook_dyld_entry
'''
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='dyld-entry-')
    with context as directory:
        temp = Path(directory)
        harness = temp / 'dyld_entry.c'
        harness.write_text(PREFIX + hook + wrapper + patch + CASES, encoding='utf-8')
        binary = temp / ('dyld_entry.exe' if sys.platform == 'win32' else 'dyld_entry')
        sanitizers = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
        for arch in ['arm64', 'arm64e']:
            flags = ['-D__arm64e__'] if arch == 'arm64e' else []
            subprocess.run(compiler + sanitizers + flags + ['-std=gnu11', '-fblocks', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare', str(harness), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=15)
            print(f'PASS: {arch} host model')
        # Compile the unchanged availability syntax too; device frameworks and
        # the actual Mach types are still checked by the full Apple build.
        syntax = temp / 'dyld_entry.m'
        if sys.platform == 'darwin':
            syntax.write_text(PREFIX + hook + production_patch, encoding='utf-8')
            syntax_compiler = compiler + ['-x', 'objective-c']
        else:
            headers = r'''
typedef _Bool bool;
#define true 1
#define false 0
#define NULL ((void*)0)
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long uintptr_t;
typedef unsigned long size_t;
#define assert(x) ((void)(x))
extern void *malloc(size_t), *memcpy(void *,const void *,size_t);
extern void free(void *);
extern int memcmp(const void *,const void *,size_t);
'''
            prefix = '\n'.join(line for line in PREFIX.splitlines() if not line.startswith('#include'))
            syntax.write_text(headers + prefix + hook + production_patch, encoding='utf-8')
            syntax_compiler = ([str(args.zig.resolve()), 'clang'] if args.zig else ['clang']) + ['-cc1', '-triple', 'arm64-apple-ios17.0.0', '-x', 'objective-c']
        for arch in ['arm64', 'arm64e']:
            flags = ['-D__arm64e__'] if arch == 'arm64e' else []
            # The unchanged iOS 15 spinlock branch negates availability; it
            # does not guard an SDK API and Clang warns about that pattern.
            subprocess.run(syntax_compiler + flags + ['-fobjc-arc', '-fblocks', '-Werror', '-Wno-unsupported-availability-guard', '-fsyntax-only', str(syntax)], check=True)
        print('PASS: production availability/entry patch Objective-C ARC syntax')


if __name__ == '__main__':
    main()
