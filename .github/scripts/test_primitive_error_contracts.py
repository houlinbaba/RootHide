#!/usr/bin/env python3
"""Execute production hookd and full-physrw error propagation with injected I/O.

The mapping, handoff, server handler and receiver initializer are real extracted
functions. Mach/kernel I/O and RPC transport are substitutes; this is not a
device reboot or SPTM validation. Old failure behavior must fail these cases.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

from test_launchd_injection import extract

ROOT = Path(__file__).resolve().parents[2]

HOOK_PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef int mach_port_t, kern_return_t;
typedef uintptr_t vm_address_t, vm_offset_t;
typedef unsigned long vm_size_t;
typedef unsigned mach_msg_type_number_t;
#define KERN_SUCCESS 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_PROT_COPY 8
#define MACH_PORT_RIGHT_SEND 1
#define MACH_PORT_VALID(p) ((p) > 0)
static int initial_result, write_result, restore_result, protect_calls, write_calls, releases, invalid_port;
static int mach_task_self(void) { return 1; }
static mach_port_t extract_task_port(mach_port_t client, mach_port_t port) {
    (void)client; (void)port; return invalid_port ? 0 : 42;
}
static int mach_port_mod_refs(int task, int port, int right, int delta) {
    (void)task; assert(port == 42 && right == MACH_PORT_RIGHT_SEND && delta == -1);
    ++releases; return 0;
}
static int vm_protect(int port, uintptr_t addr, unsigned long size, bool maximum, int prot) {
    assert(port == 42 && addr == 0x1000 && size == 1 && !maximum);
    ++protect_calls;
    if (protect_calls == 1) { assert(prot == (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)); return initial_result; }
    assert(protect_calls == 2 && prot == (VM_PROT_READ|VM_PROT_EXECUTE)); return restore_result;
}
static int vm_write(int port, uintptr_t addr, uintptr_t data, unsigned size) {
    assert(port == 42 && addr == 0x1000 && data && size == 1); ++write_calls; return write_result;
}
'''

HOOK_CASES = r'''
int main(void) {
    int errors[] = {0, 2, 5, 17};
    for (unsigned i=0; i<4; ++i) for (unsigned j=0; j<4; ++j) {
        write_result=errors[i]; restore_result=errors[j];
        protect_calls=write_calls=releases=0;
        int result=apply_hook(1, 2, 0x1000, "x", 1);
        assert(result == (restore_result ? restore_result : write_result));
        assert(protect_calls==2 && write_calls==1 && releases==1);
    }
    protect_calls=write_calls=releases=0; initial_result=2;
    assert(apply_hook(1, 2, 0x1000, "x", 1)==2 && protect_calls==1 && !write_calls && releases==1);
    protect_calls=write_calls=releases=0; initial_result=0; invalid_port=1;
    assert(apply_hook(1, 2, 0x1000, "x", 1)==-1 && !protect_calls && !write_calls && !releases);
    invalid_port=0;
    assert(apply_hook(1, 2, 0x1000, NULL, 1)==-1 && !protect_calls);
    assert(apply_hook(1, 2, 0x1000, "x", 0)==-1 && !protect_calls);
    puts("PASS: hookd preserves write/restore errors, restores RX on write failure, releases ports once");
    return 0;
}
'''

MAP_PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int pid_t;
typedef struct { int pid; } audit_token_t;
typedef void *xpc_object_t;
#define L2_BLOCK_SIZE (1ULL << 25)
#define L2_BLOCK_MASK (L2_BLOCK_SIZE - 1)
#define L1_BLOCK_SIZE (1ULL << 36)
#define L1_BLOCK_MASK (L1_BLOCK_SIZE - 1)
#define L2_BLOCK_COUNT 2048
#define PMAP_TT_L1_LEVEL 1
#define PMAP_TT_L2_LEVEL 2
#define PMAP_TT_L3_LEVEL 3
#define PPLRW_USER_MAPPING_OFFSET 0x100000000ULL
#define PERM_KRW_URW 0
#define PERM_TO_PTE(x) 0x100ULL
#define PTE_NON_GLOBAL 0x200ULL
#define PTE_OUTER_SHAREABLE 0x400ULL
#define PTE_LEVEL3_ENTRY 3ULL
#define koffsetof(type, field) 0
#define kconstant(field) (fake_##field)
#define SYSTEM_INFO_DESERIALIZE(info) ((void)(info))
#define jbinfo(field) 0
static struct { const char *rebootLogPath; } gSystemInfo;
static struct { uint64_t indexMask; } arm_tt_level[2] = {{0}, {0x7000000000ULL}};
static uint64_t fake_physBase=0x2000000, fake_physSize=L2_BLOCK_SIZE*3;
static uint64_t vm_real_kernel_page_size=16384;
static int write_error, fail_write_at, writes, successful_tables, missing_table_at, occupied, expand_error;
static int lookup_failure, task_failure, map_failure, pmap_failure, proc_releases, caffeine_starts, caffeine_stops;
static int sysinfo_error, receiver_uid, sysinfo_releases, installs, translations, surfaces, server_result;
static struct { void *kalloc_local; } gPrimitives;
static uint64_t map_ua_start(void) { return PPLRW_USER_MAPPING_OFFSET + fake_physBase; }
static uint64_t map_flags(void) { return PERM_TO_PTE(0)|PTE_NON_GLOBAL|PTE_OUTER_SHAREABLE|PTE_LEVEL3_ENTRY; }
static uint64_t kread64(uint64_t addr) { assert(addr==42); return 0x1000; }
static uint64_t kread_ptr(uint64_t addr) {
    if (addr==10) return map_failure ? 0 : 20;
    assert(addr==20); return pmap_failure ? 0 : 42;
}
static uint64_t vtophys_lvl(uint64_t ttep, uint64_t addr, uint64_t *level, void *out) {
    (void)out; assert(ttep==0x1000);
    if (*level==PMAP_TT_L2_LEVEL) {
        unsigned table=(unsigned)((addr-(map_ua_start() & ~L2_BLOCK_MASK))/L2_BLOCK_SIZE);
        return missing_table_at==(int)table+1 ? 0 : 0x2000+(uint64_t)table*16384;
    }
    *level=PMAP_TT_L3_LEVEL; return occupied ? 0x3000 : 0;
}
static uint64_t vtophys(uint64_t ttep, uint64_t addr) { (void)addr; assert(ttep==0x1000); return 0; }
static int pmap_expand_range(uint64_t pmap, uint64_t addr, uint64_t size) {
    assert(pmap==42 && addr==map_ua_start() && size==fake_physSize); return expand_error;
}
static int physwritebuf(uint64_t addr, const void *data, size_t size) {
    const uint64_t *table=data; assert(size==16384);
    uint64_t index=(addr-0x2000)/16384;
    assert(index==(uint64_t)writes);
    for (unsigned entry=0; entry<L2_BLOCK_COUNT; ++entry) {
        uint64_t expected_pa=fake_physBase+index*L2_BLOCK_SIZE+(uint64_t)entry*16384;
        assert(table[entry]==(expected_pa|map_flags()));
    }
    ++writes;
    if (writes==fail_write_at) return write_error;
    ++successful_tables; return 0;
}
static uint64_t proc_find(pid_t pid) { assert(pid==123); return lookup_failure ? 0 : 5; }
static uint64_t proc_task(uint64_t proc) { assert(proc==5); return task_failure ? 0 : 10; }
static int proc_rele(uint64_t proc) { assert(proc==5); ++proc_releases; return 0; }
static int audit_token_to_pid(audit_token_t token) { return token.pid; }
static void thread_caffeinate_start(void) { ++caffeine_starts; }
static void thread_caffeinate_stop(void) { ++caffeine_stops; }
static int physrw_pte_handoff(pid_t pid, uint64_t *asid) { (void)pid; (void)asid; assert(0); return -1; }
static void roothide_stage_log(const char *format, ...) { (void)format; }
static int getuid(void) { return receiver_uid; }
static int jbclient_root_get_sysinfo(xpc_object_t *info) { *info=(void *)1; return sysinfo_error; }
static void xpc_release(xpc_object_t info) { assert(info==(void *)1); ++sysinfo_releases; }
static int roothide_reboot_log_configure(const char *path) { (void)path; return 0; }
static int libjailbreak_physrw_init(bool handed_off) { assert(handed_off); ++installs; return 0; }
static int libjailbreak_physrw_pte_init(bool handed_off, uint64_t asid) { (void)handed_off; (void)asid; assert(0); return -1; }
static void libjailbreak_translation_init(void) { ++translations; }
static void libjailbreak_IOSurface_primitives_init(void) { ++surfaces; }
static void arm64_kcall_init(void) { assert(0); }
'''

MAP_BRIDGE = r'''
static int jbclient_root_get_physrw(bool single, uint64_t *asid) {
    audit_token_t token={123};
    /* Substitute only the request/reply transport, preserving the server result. */
    server_result=boomerang_get_physrw(&token, single, asid); return server_result;
}
'''

MAP_CASES = r'''
static void reset(void) {
    fail_write_at=writes=successful_tables=missing_table_at=occupied=expand_error=0;
    lookup_failure=task_failure=map_failure=pmap_failure=proc_releases=caffeine_starts=caffeine_stops=0;
    sysinfo_error=receiver_uid=sysinfo_releases=installs=translations=surfaces=0; server_result=999;
}
int main(void) {
    int errors[]={-1, -5, 5};
    for (unsigned i=0; i<3; ++i) for (int position=1; position<=3; ++position) {
        reset(); fail_write_at=position; write_error=errors[i];
        assert(jbclient_initialize_primitives_internal(false)==-1);
        assert(server_result==-13 && writes==position && successful_tables==position-1);
        assert(proc_releases==1 && caffeine_starts==1 && caffeine_stops==1 && sysinfo_releases==1);
        assert(!installs && !translations && !surfaces);
    }
    reset(); assert(jbclient_initialize_primitives_internal(false)==0);
    assert(!server_result && writes==3 && successful_tables==3);
    assert(installs==1 && translations==1 && surfaces==1 && proc_releases==1 && caffeine_stops==1);
    reset(); missing_table_at=2;
    assert(jbclient_initialize_primitives_internal(false)==-1 && server_result==-12 && writes==1 && !installs);
    reset(); occupied=1;
    assert(jbclient_initialize_primitives_internal(false)==-1 && server_result==-11 && !writes && !installs);
    reset(); expand_error=-7;
    assert(jbclient_initialize_primitives_internal(false)==-1 && server_result==-11 && !writes && !installs);
    reset(); lookup_failure=1;
    assert(jbclient_initialize_primitives_internal(false)==-1 && server_result==-2 && !proc_releases && !installs);
    reset(); task_failure=1;
    assert(jbclient_initialize_primitives_internal(false)==-1 && server_result==-3 && proc_releases==1 && !installs);
    reset(); map_failure=1;
    assert(jbclient_initialize_primitives_internal(false)==-1 && server_result==-4 && !installs);
    reset(); pmap_failure=1;
    assert(jbclient_initialize_primitives_internal(false)==-1 && server_result==-5 && !installs);
    reset(); sysinfo_error=-1;
    assert(jbclient_initialize_primitives_internal(false)==-1 && !caffeine_starts && !installs);
    reset(); receiver_uid=501;
    assert(jbclient_initialize_primitives_internal(false)==-1 && !sysinfo_releases && !installs);
    puts("PASS: full-physrw write failure crosses mapper/handoff/server/receiver; partial mappings never enable receiver primitives");
    return 0;
}
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args=parser.parse_args()
    compiler=[str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
    util=(ROOT/'BaseBin/libjailbreak/src/util.c').read_text(encoding='utf-8')
    hook=extract((ROOT/'BaseBin/hookd/src/main.c').read_text(encoding='utf-8'), 'int apply_hook(')
    mapper=extract(util, 'int pmap_map_in_with_flags(')
    mapping=extract(util, 'int pmap_map_in(')
    handoff=extract((ROOT/'BaseBin/libjailbreak/src/physrw.c').read_text(encoding='utf-8'), 'int physrw_handoff(')
    server=extract((ROOT/'BaseBin/libjailbreak/src/jbserver_boomerang.c').read_text(encoding='utf-8'), 'int boomerang_get_physrw(')
    receiver=extract((ROOT/'BaseBin/libjailbreak/src/main.c').read_text(encoding='utf-8'), 'int jbclient_initialize_primitives_internal(')
    context=nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='primitive-contracts-')
    with context as directory:
        directory=Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        def execute(name, source, must_fail=False):
            path=directory/(name+'.c')
            binary=directory/(name+('.exe' if sys.platform=='win32' else ''))
            path.write_text(source, encoding='utf-8')
            command=compiler+['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-variable']
            if sys.platform=='darwin': command+=['-fsanitize=address,undefined']
            subprocess.run(command+[str(path), '-o', str(binary)], check=True, timeout=60)
            result=subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            if must_fail:
                assert result.returncode!=0, f'{name}: defective behavior was not rejected'
                print(f'PASS: {name} defective behavior rejected')
            else:
                if result.returncode:
                    raise RuntimeError(f'{name}: {result.stdout}\n{result.stderr}')
                print(result.stdout, end='')

        execute('hook', HOOK_PREFIX+hook+HOOK_CASES)
        chain=MAP_PREFIX+mapper+mapping+handoff+server+MAP_BRIDGE+receiver+MAP_CASES
        execute('handoff', chain)
        broken_hook=hook.replace('return kr;\n}', 'return KERN_SUCCESS;\n}')
        assert broken_hook!=hook
        execute('hook-write-hidden', HOOK_PREFIX+broken_hook+HOOK_CASES, True)
        broken_restore=hook.replace('return restoreKr;', 'return restoreKr != KERN_SUCCESS;')
        assert broken_restore!=hook
        execute('hook-restore-collapsed', HOOK_PREFIX+broken_restore+HOOK_CASES, True)
        start=mapper.index('\t\tif (physwritebuf(level2Table,')
        end=mapper.index('\n\t\t}', start)+len('\n\t\t}')
        broken_mapper=mapper[:start]+'\t\tphyswritebuf(level2Table, tableToWrite, vm_real_kernel_page_size);'+mapper[end:]
        execute('handoff-write-hidden', MAP_PREFIX+broken_mapper+mapping+handoff+server+MAP_BRIDGE+receiver+MAP_CASES, True)


if __name__=='__main__':
    main()
