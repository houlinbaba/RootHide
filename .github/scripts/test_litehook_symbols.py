#!/usr/bin/env python3
"""Exercise production Mach-O symbol lookup and systemhook's missing-target path.

Fixtures cover zero/nonzero preferred addresses and unequal file/VM offsets.
They do not simulate dyld, sandbox extensions or device pointer authentication.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'BaseBin/_external/modules/litehook/src/litehook.c'


def extract(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for pos in range(opening, len(source)):
        depth += (source[pos] == '{') - (source[pos] == '}')
        if not depth:
            return source[start:pos + 1]
    raise ValueError(signature)


PREFIX = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
typedef struct mach_header_64 mach_header_u;
typedef struct segment_command_64 segment_command_u;
typedef struct nlist_64 nlist_u;
#define LC_SEGMENT_U LC_SEGMENT_64
#else
typedef struct { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved; } mach_header_u;
struct load_command { uint32_t cmd, cmdsize; };
struct symtab_command { uint32_t cmd, cmdsize, symoff, nsyms, stroff, strsize; };
typedef struct {
    uint32_t cmd, cmdsize; char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    int32_t maxprot, initprot; uint32_t nsects, flags;
} segment_command_u;
typedef struct { union { uint32_t n_strx; } n_un; uint8_t n_type, n_sect; uint16_t n_desc; uint64_t n_value; } nlist_u;
#define LC_SYMTAB 2
#define LC_SEGMENT_U 0x19
#define N_TYPE 0x0e
#define N_SECT 0x0e
#define N_STAB 0xe0
#endif
_Static_assert(sizeof(mach_header_u)==32, "Mach-O header ABI");
_Static_assert(sizeof(segment_command_u)==72, "segment ABI");
_Static_assert(sizeof(struct symtab_command)==24, "symtab ABI");
_Static_assert(sizeof(nlist_u)==16, "nlist ABI");
static unsigned sign_calls;
static void *_litehook_sign_if_executable(void *p) { sign_calls++; return p; }
static _Alignas(16) uint8_t image[0x10000];
static mach_header_u *header;
static segment_command_u *text_segment, *linkedit_segment;
static struct symtab_command *symtab;
static nlist_u *entries;
static char *names;
static void *expected_symbol;
static void *append_command(size_t size) {
    void *p=image+sizeof(*header)+header->sizeofcmds;
    header->ncmds++; header->sizeofcmds+=(uint32_t)size; return p;
}
static segment_command_u *segment(const char *name, uint64_t vmaddr, uint64_t fileoff, uint64_t filesize) {
    segment_command_u *s=append_command(sizeof(*s));
    s->cmd=LC_SEGMENT_U;s->cmdsize=sizeof(*s);strcpy(s->segname,name);
    s->vmaddr=vmaddr;s->vmsize=0x1000;s->fileoff=fileoff;s->filesize=filesize;return s;
}
static void table(void) {
    symtab=append_command(sizeof(*symtab));symtab->cmd=LC_SYMTAB;symtab->cmdsize=sizeof(*symtab);
    symtab->symoff=0x1880;symtab->nsyms=1;symtab->stroff=0x1a00;symtab->strsize=0x80;
}
static void setup(uint64_t preferred, bool pagezero, bool reordered) {
    memset(image,0,sizeof(image));header=(mach_header_u *)image;
    header->magic=0xfeedfacf;
    if(pagezero) segment("__PAGEZERO",0,0,0);
    if(reordered) {
        linkedit_segment=segment("__LINKEDIT",preferred+0x2000,0x1800,0x1000);table();
        text_segment=segment("__TEXT",preferred,0,0x1000);
    } else {
        text_segment=segment("__TEXT",preferred,0,0x1000);table();
        linkedit_segment=segment("__LINKEDIT",preferred+0x2000,0x1800,0x1000);
    }
    entries=(nlist_u *)(image+0x2080);names=(char *)(image+0x2200);
    memcpy(names,"\0___fcntl\0",10);
    entries[0].n_un.n_strx=1;entries[0].n_type=N_SECT;entries[0].n_sect=1;
    entries[0].n_value=preferred+0x400;expected_symbol=image+0x400;sign_calls=0;
}
typedef int kern_return_t;
static unsigned hook_calls, log_calls;
static int hook_result, last_result;
static char last_event[80];
static const mach_header_u *get_dyld_mach_header(void) { return header; }
static const char *symbol_test_getprogname(void) { return "RootHide"; }
#define getprogname symbol_test_getprogname
static int __fcntl(int fd, int op, ...) { (void)fd;(void)op;return 0; }
static kern_return_t litehook_hook_function(void *source, void *target) {
    if(source!=(void *)__fcntl || target!=expected_symbol) abort();
    hook_calls++;return hook_result;
}
static void roothide_app_startup_diagnostic(const char *app,const char *event,int result) {
    if(strcmp(app,"RootHide")) abort();
    log_calls++;snprintf(last_event,sizeof(last_event),"%s",event);last_result=result;
}
'''

CASES = r'''
#define CHECK(condition) do { if(!(condition)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#condition);return 1; } } while(0)
int main(void) {
    const uint64_t bases[]={0,0x4000,UINT64_C(0x180000000),UINT64_C(0x1bb196000)};
    for(unsigned b=0;b<sizeof(bases)/sizeof(bases[0]);b++) {
        for(unsigned mode=0;mode<4;mode++) {
            setup(bases[b],mode&1,mode&2);
            CHECK(litehook_find_symbol(header,"___fcntl")==expected_symbol && sign_calls==1);
            CHECK(!litehook_find_symbol(header,"___missing") && sign_calls==1);
        }
    }
    CHECK(!litehook_find_symbol(NULL,"___fcntl"));
    CHECK(!litehook_find_symbol(header,NULL));
    setup(0x4000,false,false);symtab->cmdsize=sizeof(struct load_command);
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);text_segment->cmdsize=0;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);text_segment->cmdsize=sizeof(struct load_command);
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);header->sizeofcmds--;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);header->ncmds++;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);symtab->cmd=0;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);strcpy(linkedit_segment->segname,"__DATA");
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);symtab->symoff=0x1700;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);symtab->stroff=0x1700;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);symtab->nsyms=UINT32_MAX;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);symtab->strsize=UINT32_MAX;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);linkedit_segment->filesize=0x80;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);linkedit_segment->vmaddr=UINT64_MAX;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);linkedit_segment->filesize=UINT64_MAX;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);entries[0].n_value=0x3fff;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);entries[0].n_un.n_strx=symtab->strsize;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);entries[0].n_un.n_strx=0;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);entries[0].n_type=N_STAB|N_SECT;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);entries[0].n_type=1;
    CHECK(!litehook_find_symbol(header,"___fcntl"));
    setup(0x4000,false,false);memset(names+1,'X',symtab->strsize-1);
    CHECK(!litehook_find_symbol(header,"___fcntl") && !sign_calls);
    setup(0x4000,false,false);symtab->nsyms=3;
    entries[2]=entries[0];entries[0].n_type=N_STAB|N_SECT;entries[1].n_un.n_strx=UINT32_MAX;
    CHECK(litehook_find_symbol(header,"___fcntl")==expected_symbol && sign_calls==1);
    setup(0x4000,false,false);names[1]='!';hook_calls=log_calls=0;
    hook_dyld_fcntl();
    CHECK(!hook_calls && log_calls==1 && last_result==-1 && !strcmp(last_event,"dyld_fcntl.lookup.failed"));
    setup(0x4000,false,false);hook_calls=log_calls=0;hook_result=7;
    hook_dyld_fcntl();
    CHECK(hook_calls==1 && log_calls==1 && last_result==7 && !strcmp(last_event,"dyld_fcntl.hook.end"));
    setup(0,false,false);hook_result=0;hook_calls=log_calls=0;
    hook_dyld_fcntl();CHECK(hook_calls==1 && log_calls==1 && last_result==0);
    puts("PASS: production symbol lookup handles preferred addresses, load-command order, table/name bounds and missing hook targets");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    symbol = extract(args.source.read_text(encoding='utf-8'), 'void *litehook_find_symbol(')
    systemhook = (ROOT / 'BaseBin/systemhook/src/main.c').read_text(encoding='utf-8')
    helper = extract(systemhook, 'static void hook_dyld_fcntl(')
    initializer = extract(systemhook, '__attribute__((constructor)) static void initializer(')
    assert 'hook_dyld_fcntl();' in initializer
    workflow = (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    assert 'litehook-symbol-slide.patch' in workflow and 'test_litehook_symbols.py' in workflow
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror']
    sanitizer = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
    scratch = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='litehook-symbols-')
    with scratch as directory:
        temp = Path(directory)
        temp.mkdir(parents=True, exist_ok=True)
        c = temp / 'symbols.c'
        binary = temp / ('symbols.exe' if sys.platform == 'win32' else 'symbols')
        c.write_text(PREFIX + symbol + '\n' + helper + CASES, encoding='utf-8')
        subprocess.run(compiler + sanitizer + flags + [str(c), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        if args.zig and sys.platform != 'darwin':
            for arch in ('aarch64', 'x86_64'):
                subprocess.run(compiler + ['-target', arch + '-macos'] + flags + ['-c', str(c), '-o', str(temp / (arch + '.o'))], check=True)
            print('PASS: Darwin Mach-O header ABI cross-compilation (arm64 and x86_64)')
        mutants = {
            'old_linkedit': symbol.replace('(uintptr_t)header + (linkeditSegCommand->vmaddr - vmBase);', '(uintptr_t)header + linkeditSegCommand->vmaddr;'),
            'old_symbol': symbol.replace('(uintptr_t)header + (symEntry->n_value - vmBase)', '(uintptr_t)header + symEntry->n_value'),
        }
        if args.baseline:
            mutants['pinned_baseline'] = extract(args.baseline.read_text(encoding='utf-8'), 'void *litehook_find_symbol(')
        for name, mutant in mutants.items():
            assert mutant != symbol
            negative = temp / (name + '.c')
            negative_binary = temp / (name + ('.exe' if sys.platform == 'win32' else ''))
            negative.write_text(PREFIX + mutant + '\n' + helper + CASES, encoding='utf-8')
            # The unmodified pinned source compares uint32_t slide with -1.
            negative_flags = flags + (['-Wno-sign-compare'] if name == 'pinned_baseline' else [])
            subprocess.run(compiler + sanitizer + negative_flags + [str(negative), '-o', str(negative_binary)], check=True)
            result = subprocess.run([str(negative_binary)], capture_output=True, timeout=15)
            assert result.returncode != 0 and b'FAIL line' in result.stderr, f'{name} did not expose the address defect'
            print(f'PASS: negative regression rejects {name}')


if __name__ == '__main__':
    main()
