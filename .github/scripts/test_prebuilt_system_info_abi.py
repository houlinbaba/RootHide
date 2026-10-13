#!/usr/bin/env python3
"""Check the shared C layout against the bundled framework's frozen ABI.

The framework is copied into the app without recompiling its consumers of
gSystemInfo. Compile every frozen member offset for both iOS arm64 variants;
also verify the ClearSword instructions/import that establish the ABI evidence.
No exploit or kernel operation is executed.
"""
import argparse
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from test_launchd_injection import extract

ROOT = Path(__file__).resolve().parents[2]
TYPES = "typedef __UINT64_TYPE__ uint64_t;\ntypedef __UINT32_TYPE__ uint32_t;\n#define bool _Bool\n"

XPC_HEADER = r'''
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef void *xpc_object_t;
const char *xpc_dictionary_get_string(xpc_object_t dict, const char *key);
void xpc_dictionary_set_string(xpc_object_t dict, const char *key, const char *value);
uint64_t xpc_dictionary_get_uint64(xpc_object_t dict, const char *key);
void xpc_dictionary_set_uint64(xpc_object_t dict, const char *key, uint64_t value);
double xpc_dictionary_get_double(xpc_object_t dict, const char *key);
void xpc_dictionary_set_double(xpc_object_t dict, const char *key, double value);
bool xpc_dictionary_get_bool(xpc_object_t dict, const char *key);
void xpc_dictionary_set_bool(xpc_object_t dict, const char *key, bool value);
'''

ROUNDTRIP = r'''
#include <assert.h>
#include <stdio.h>
#include "info.h"
struct system_info gSystemInfo;
struct entry {
    const char *key;
    int type;
    union { char *string; uint64_t integer; double floating; bool boolean; } value;
};
struct dictionary { struct entry entries[256]; unsigned count; };
static struct entry *entry(xpc_object_t object, const char *key, bool create) {
    struct dictionary *dict = object;
    for (unsigned i = 0; i < dict->count; ++i) {
        if (!strcmp(dict->entries[i].key, key)) return &dict->entries[i];
    }
    if (!create) return NULL;
    assert(dict->count < 256);
    struct entry *result = &dict->entries[dict->count++];
    result->key = key;
    return result;
}
const char *xpc_dictionary_get_string(xpc_object_t dict, const char *key) {
    struct entry *e = entry(dict, key, false);
    return e && e->type == 1 ? e->value.string : NULL;
}
void xpc_dictionary_set_string(xpc_object_t dict, const char *key, const char *value) {
    struct entry *e = entry(dict, key, true);
    if (e->type == 1) free(e->value.string);
    e->type = 1;
    e->value.string = strdup(value);
    assert(e->value.string);
}
#define NUMBER_ACCESSORS(name, ctype, tag, member) \
ctype xpc_dictionary_get_##name(xpc_object_t dict, const char *key) { \
    struct entry *e = entry(dict, key, false); \
    return e && e->type == tag ? e->value.member : 0; \
} \
void xpc_dictionary_set_##name(xpc_object_t dict, const char *key, ctype value) { \
    struct entry *e = entry(dict, key, true); \
    assert(e->type != 1); e->type = tag; e->value.member = value; \
}
NUMBER_ACCESSORS(uint64, uint64_t, 2, integer)
NUMBER_ACCESSORS(double, double, 3, floating)
NUMBER_ACCESSORS(bool, bool, 4, boolean)

int main(void) {
    struct dictionary dict = {0}, legacy = {0};
    const char *path = "/var/mobile/Containers/Data/Application/01234567-89AB-cdef-0123-456789abcdef/Documents/RootHideReboot.log";
    gSystemInfo.kernelConstant.slide = 0xfeed0000;
    gSystemInfo.kernelStruct.inpcb.socket = 0x38;
    gSystemInfo.kernelStruct.inpcb.icmp6filt = 0x138;
    gSystemInfo.kernelStruct.socket.usecount = 0x254;
    gSystemInfo.jailbreakInfo.preserveDeveloperMode = true;
    gSystemInfo.jailbreakSettings.jetsamMultiplier = 2.5;
    gSystemInfo.rebootLogPath = strdup(path);
    SYSTEM_INFO_SERIALIZE(&dict);
    assert(!strcmp(xpc_dictionary_get_string(&dict, "jailbreakInfo.rebootLogPath"), path));
    assert(!entry(&dict, "rebootLogPath", false));
    free(gSystemInfo.rebootLogPath);
    memset(&gSystemInfo, 0, sizeof(gSystemInfo));
    SYSTEM_INFO_DESERIALIZE(&dict);
    assert(gSystemInfo.kernelConstant.slide == 0xfeed0000);
    assert(gSystemInfo.kernelStruct.inpcb.socket == 0x38);
    assert(gSystemInfo.kernelStruct.inpcb.icmp6filt == 0x138);
    assert(gSystemInfo.kernelStruct.socket.usecount == 0x254);
    assert(gSystemInfo.jailbreakInfo.preserveDeveloperMode);
    assert(gSystemInfo.jailbreakSettings.jetsamMultiplier == 2.5);
    assert(!strcmp(gSystemInfo.rebootLogPath, path));
    assert(gSystemInfo.rebootLogPath != xpc_dictionary_get_string(&dict, "jailbreakInfo.rebootLogPath"));
    xpc_dictionary_set_string(&dict, "jailbreakInfo.rebootLogPath", "replacement-journal");
    SYSTEM_INFO_DESERIALIZE(&dict);
    assert(!strcmp(gSystemInfo.rebootLogPath, "replacement-journal"));
    // Missing extension retains the existing safe-string helper semantics.
    SYSTEM_INFO_DESERIALIZE(&legacy);
    assert(!strcmp(gSystemInfo.rebootLogPath, "replacement-journal"));
    free(gSystemInfo.rebootLogPath);
    for (unsigned i = 0; i < dict.count; ++i) {
        if (dict.entries[i].type == 1) free(dict.entries[i].value.string);
    }
    puts("PASS: production system_info serialization preserves typed fields, journal wire key and owned string copies");
    return 0;
}
'''


def verify_binary(fixture):
    binary = (ROOT / fixture['framework']).read_bytes()
    assert hashlib.sha256(binary).hexdigest() == fixture['sha256'], 'Framework changed: re-audit its shared ABI before updating the fixture'
    assert struct.unpack_from('<I', binary)[0] == 0xfeedfacf
    position = 32
    fixups = None
    for _ in range(struct.unpack_from('<I', binary, 16)[0]):
        command, size = struct.unpack_from('<II', binary, position)
        if command == 0x80000034:
            fixups = struct.unpack_from('<I', binary, position + 8)[0]
        position += size
    assert fixups is not None
    _, _, imports, strings, count, format_, symbol_format = struct.unpack_from('<7I', binary, fixups)
    assert format_ == 1 and symbol_format == 0
    evidence = fixture['clearSwordReads']
    # The ADRP/LDR pair loads x8 from the imported gSystemInfo GOT slot.
    page = evidence['gotFileOffset'] & ~4095
    address = evidence['baseLoadFileOffset']
    adrp, ldr = struct.unpack_from('<II', binary, address)
    immediate = (((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    assert adrp & 0x9f00001f == 0x90000008
    assert (address & ~4095) + (immediate << 12) == page
    assert ldr & 0xffc003ff == 0xf9400108
    assert page + ((ldr >> 10) & 4095) * 8 == evidence['gotFileOffset']
    pointer = struct.unpack_from('<Q', binary, evidence['gotFileOffset'])[0]
    assert pointer >> 63 == 1
    ordinal = pointer & 0xffffff
    assert ordinal < count
    imported = struct.unpack_from('<I', binary, fixups + imports + ordinal * 4)[0]
    name = binary[fixups + strings + (imported >> 9):].split(b'\0', 1)[0]
    assert name == b'_gSystemInfo'
    for read in evidence['fields']:
        instruction = struct.unpack_from('<I', binary, read['instructionFileOffset'])[0]
        assert instruction & 0xffc003e0 == 0xb9400120  # LDR Wt, [X9, #imm]
        assert ((instruction >> 10) & 4095) * 4 == fixture['members'][read['member']]
    print('PASS: bundled ClearSword reads the imported gSystemInfo at the frozen offsets', flush=True)


def layout_assertions(definition, fixture):
    source = TYPES + definition + ';\n'
    source += '_Static_assert(sizeof(void *) == 8, "requires 64-bit ABI");\n'
    for member, offset in fixture['members'].items():
        source += f'_Static_assert(__builtin_offsetof(struct system_info, {member}) == {offset}, "ABI drift: {member}");\n'
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    fixture = json.loads((ROOT / '.github/fixtures/prebuilt-system-info-abi.json').read_text(encoding='utf-8'))
    verify_binary(fixture)
    header = (ROOT / 'BaseBin/libjailbreak/src/info.h').read_text(encoding='utf-8')
    definition = extract(header, 'struct system_info {')
    compiler = [str(args.zig.resolve()), 'clang', '-cc1'] if args.zig else (['xcrun', 'clang', '-cc1'] if sys.platform == 'darwin' else ['clang', '-cc1'])
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='prebuilt-abi-')
    with context as directory:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / 'layout.c'
        probe.write_text(layout_assertions(definition, fixture), encoding='utf-8')
        for target in ('arm64-apple-ios17.0.0', 'arm64e-apple-ios17.0.0'):
            subprocess.run(compiler + ['-triple', target, '-std=c11', '-fsyntax-only', str(probe)], check=True, timeout=30)
            print(f'PASS: {target} preserves {len(fixture["members"])} frozen shared offsets', flush=True)
        # Reintroduce an eight-byte field in jailbreakInfo: the guard must fail.
        mutant = definition.replace('} jailbreakInfo;', 'char *abiDrift;\n\t} jailbreakInfo;')
        assert mutant != definition
        probe.write_text(layout_assertions(mutant, fixture), encoding='utf-8')
        result = subprocess.run(compiler + ['-triple', 'arm64-apple-ios17.0.0', '-std=c11', '-fsyntax-only', str(probe)], capture_output=True, text=True, timeout=30)
        assert result.returncode != 0 and 'ABI drift:' in result.stderr
        print('PASS: a pointer inserted into jailbreakInfo is rejected before packaging', flush=True)
        # Include the complete production header; only XPC storage is replaced.
        (directory / 'mach').mkdir(exist_ok=True)
        (directory / 'mach/mach.h').write_text('', encoding='utf-8')
        (directory / 'xpc').mkdir(exist_ok=True)
        (directory / 'xpc/xpc.h').write_text(XPC_HEADER, encoding='utf-8')
        harness = directory / 'roundtrip.c'
        harness.write_text(ROUNDTRIP, encoding='utf-8')
        binary = directory / ('roundtrip.exe' if sys.platform == 'win32' else 'roundtrip')
        host_compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
        command = host_compiler + ['-std=c11', '-D_GNU_SOURCE', '-Wall', '-Wextra', '-Werror']
        if sys.platform == 'darwin':
            command += ['-fsanitize=address,undefined']
        subprocess.run(command + ['-I', str(directory), '-I', str(ROOT / 'BaseBin/libjailbreak/src'), str(harness), '-o', str(binary)], check=True, timeout=30)
        subprocess.run([str(binary)], check=True, timeout=15)


if __name__ == '__main__':
    main()
