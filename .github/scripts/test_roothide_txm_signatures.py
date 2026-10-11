#!/usr/bin/env python3
"""Exercise production TXM policy, directory traversal and signature writes.

The macOS harness extracts the real preparation function, uses CommonCrypto
for hashes, and mocks ChOma/file operations. It does not emulate TXM or XNU.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'BaseBin/libjailbreak/src/roothider'


def extract(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for pos in range(opening, len(source)):
        if source[pos] == '{':
            depth += 1
        elif source[pos] == '}':
            depth -= 1
            if not depth:
                return source[start:pos + 1]
    raise ValueError(signature)


PREFIX = r'''
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <libkern/OSByteOrder.h>
#include <CommonCrypto/CommonDigest.h>
#include "signature_policy.h"
#define BIG_TO_HOST(v) OSSwapBigToHostInt32(v)
#define HOST_TO_BIG(v) OSSwapHostToBigInt32(v)
#define BIG_TO_HOST_APPLIER(v) ((v) = BIG_TO_HOST(v))
#define CODE_DIRECTORY_APPLY_BYTE_ORDER(v, apply) do { \
    apply((v)->magic); apply((v)->length); apply((v)->version); apply((v)->flags); \
    apply((v)->hashOffset); apply((v)->identOffset); apply((v)->nSpecialSlots); \
    apply((v)->nCodeSlots); apply((v)->codeLimit); apply((v)->spare2); \
    apply((v)->scatterOffset); apply((v)->teamOffset); } while (0)
#define BLOB_INDEX_APPLY_BYTE_ORDER(v, apply) do { apply((v)->type); apply((v)->offset); } while (0)
#define CS_CDHASH_LEN 20
#define CSSLOT_CODEDIRECTORY 0
#define CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000
#define CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT 0x1005
#define CS_HASHTYPE_SHA160_160 1
#define CS_HASHTYPE_SHA256_256 2
#define CS_HASHTYPE_SHA256_160 3
#define CS_HASHTYPE_SHA384_384 4
#define FILE_STREAM_SIZE_AUTO 0
#define FILE_STREAM_FLAG_WRITABLE 1
static void fake_log(const char *format, ...) { (void)format; }
#define JBLogDebug(...) fake_log(__VA_ARGS__)
#define JBLogError(...) fake_log(__VA_ARGS__)
typedef struct {
    uint32_t magic, length, version, flags, hashOffset, identOffset, nSpecialSlots, nCodeSlots, codeLimit;
    uint8_t hashSize, hashType, platform, pageSize;
    uint32_t spare2, scatterOffset, teamOffset;
} CS_CodeDirectory;
typedef struct { uint32_t type, offset; } CS_BlobIndex;
typedef struct { uint32_t magic, length, count; CS_BlobIndex index[]; } CS_SuperBlob;
typedef struct { uint8_t *data; size_t size; } MemoryStream;
typedef struct Blob { struct Blob *next; uint32_t type; MemoryStream *stream; } CS_DecodedBlob;
typedef struct { CS_DecodedBlob *firstBlob; } CS_DecodedSuperBlob;
typedef struct { struct { uint64_t offset; } archDescriptor; } MachO;
typedef struct { MemoryStream *stream; MachO macho; } Fat;
_Alignas(8) static uint8_t image[8192];
static CS_DecodedSuperBlob decoded;
static CS_DecodedBlob blobs[2];
static MemoryStream blobStreams[2];
static bool sptm = true, fail_fat, fail_hash, cms_signed;
static int stream_count, writes, fail_write;
static uint64_t brand = 0x123456789abcdef0;
#define ksymbol(symbol) (sptm)
#define jbinfo(member) (brand)
static int fake_access(const char *path, int mode) { (void)path; (void)mode; return 0; }
#define access fake_access
static bool isRemovableBundlePath(const char *path) { (void)path; return false; }
static bool hasTrollstoreLiteMarker(const char *path) { (void)path; return true; }
static MemoryStream *file_stream_init_from_path(const char *path, int offset, int size, int flags) {
    (void)path; (void)offset; (void)size; (void)flags;
    MemoryStream *stream = malloc(sizeof(*stream)); assert(stream);
    *stream = (MemoryStream){image, sizeof(image)}; ++stream_count; return stream;
}
static void memory_stream_free(MemoryStream *stream) { --stream_count; free(stream); }
static Fat *fat_init_from_memory_stream(MemoryStream *stream) {
    if (fail_fat) return NULL;
    Fat *fat = calloc(1, sizeof(*fat)); assert(fat); fat->stream = stream; return fat;
}
static void fat_free(Fat *fat) { memory_stream_free(fat->stream); free(fat); }
static MachO *fat_find_preferred_slice(Fat *fat) { return &fat->macho; }
static void fat_enumerate_slices(Fat *fat, void (^handler)(MachO *, bool *)) {
    bool stop = false; handler(&fat->macho, &stop);
}
static int memory_stream_read(MemoryStream *stream, uint64_t offset, size_t size, void *out) {
    if (offset > stream->size || size > stream->size - offset) return -1;
    memcpy(out, stream->data + offset, size); return 0;
}
static int memory_stream_write(MemoryStream *stream, uint64_t offset, size_t size, const void *data) {
    if (++writes == fail_write || offset > stream->size || size > stream->size - offset) return -1;
    memcpy(stream->data + offset, data, size); return 0;
}
static size_t csd_blob_get_size(CS_DecodedBlob *blob) { return blob->stream->size; }
static int csd_blob_read(CS_DecodedBlob *blob, uint64_t offset, size_t size, void *out) {
    return memory_stream_read(blob->stream, offset, size, out);
}
static void macho_enumerate_load_commands(MachO *macho,
    void (^handler)(struct load_command, uint64_t, void *, bool *)) {
    (void)macho; bool stop = false;
    struct load_command cmd; memcpy(&cmd, image + 32, sizeof(cmd));
    handler(cmd, 32, image + 32, &stop);
    if (!stop) { memcpy(&cmd, image + 256, sizeof(cmd)); handler(cmd, 256, image + 256, &stop); }
}
static CS_SuperBlob *macho_read_code_signature(MachO *macho) {
    (void)macho; uint32_t length = BIG_TO_HOST(((CS_SuperBlob *)(image + 4096))->length);
    void *result = malloc(length); assert(result); memcpy(result, image + 4096, length); return result;
}
static CS_DecodedSuperBlob *csd_superblob_decode(CS_SuperBlob *superblob) { (void)superblob; return &decoded; }
static bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob) { (void)superblob; return !cms_signed; }
static void csd_superblob_free(CS_DecodedSuperBlob *superblob) { (void)superblob; }
static CS_DecodedBlob *csd_superblob_find_best_code_directory(CS_DecodedSuperBlob *superblob) {
    return superblob->firstBlob;
}
static CS_DecodedBlob *csd_superblob_find_blob(CS_DecodedSuperBlob *superblob, uint32_t type, void *index) {
    (void)index;
    for (CS_DecodedBlob *blob = superblob->firstBlob; blob; blob = blob->next)
        if (blob->type == type) return blob;
    return NULL;
}
static uint8_t csd_code_directory_get_hash_type(CS_DecodedBlob *blob) { return blob->stream->data[37]; }
static bool code_directory_calculate_page_hash(CS_CodeDirectory *directory, MachO *macho, int slot, uint8_t *out) {
    (void)macho; assert(slot == 0);
    if (fail_hash) return false;
    // Fixtures use SHA-256; hashing reads the current image after the real jbrand write.
    assert(directory->hashType == 2 && directory->hashSize == 32);
    CC_SHA256(image, 4096, out); return true;
}
int ensure_randomized_cdhash_for_slice(const char *, uint64_t, void *);
'''

CASES = r'''
static void put32(uint8_t *out, uint32_t value) { value = HOST_TO_BIG(value); memcpy(out, &value, 4); }
static uint32_t get32(const uint8_t *in) { uint32_t value; memcpy(&value, in, 4); return BIG_TO_HOST(value); }
static uint8_t *directory(int index) { return image + 4096 + 32 + index * 128; }
static void reset(int count) {
    assert(stream_count == 0); memset(image, 0, sizeof(image));
    writes = 0; fail_write = 0; fail_fat = false; fail_hash = false; cms_signed = false; sptm = true;
    struct segment_command_64 segment = { .cmd = LC_SEGMENT_64, .cmdsize = sizeof(segment) + sizeof(struct section_64), .nsects = 1 };
    memcpy(segment.segname, "__TEXT", 7); memcpy(image + 32, &segment, sizeof(segment));
    struct section_64 section = {0}; memcpy(section.segname, "__TEXT", 7);
    memcpy(image + 32 + sizeof(segment), &section, sizeof(section));
    struct linkedit_data_command command = {.cmd = LC_CODE_SIGNATURE, .cmdsize = sizeof(command), .dataoff = 4096, .datasize = 32 + count * 128};
    memcpy(image + 256, &command, sizeof(command));
    CS_SuperBlob *superblob = (void *)(image + 4096);
    superblob->magic = HOST_TO_BIG(0xfade0cc0); superblob->length = HOST_TO_BIG(command.datasize); superblob->count = HOST_TO_BIG(count);
    for (int i = 0; i < count; ++i) {
        uint8_t *cd = directory(i);
        put32(cd, 0xfade0c02); put32(cd + 4, 128); put32(cd + 8, 0x20200);
        put32(cd + 16, 96); put32(cd + 28, 1); put32(cd + 32, 4096);
        cd[36] = 32; cd[37] = 2; cd[39] = 12;
        CC_SHA256(image, 4096, cd + 96);
        uint32_t type = i == 0 ? 0 : 0x1000;
        superblob->index[i] = (CS_BlobIndex){HOST_TO_BIG(type), HOST_TO_BIG(32 + i * 128)};
        blobStreams[i] = (MemoryStream){cd, 128};
        blobs[i] = (CS_DecodedBlob){i + 1 < count ? &blobs[i + 1] : NULL, type, &blobStreams[i]};
    }
    decoded.firstBlob = &blobs[0];
}
static void policy_cases(void) {
    uint32_t flags;
    reset(1); uint8_t *cd = directory(0);
    for (unsigned team = 0; team < 2; ++team) {
        put32(cd + 48, team ? 64 : 0); memcpy(cd + 64, "TEAM\0", 5);
        for (unsigned adhoc = 0; adhoc < 2; ++adhoc) {
            put32(cd + 12, 0x10000 | (adhoc ? 2 : 0));
            assert(roothide_signature_normalized_flags(cd, 128, true, &flags));
            assert(flags == (0x10000u | (team ? 0u : 2u)));
            assert(roothide_signature_normalized_flags(cd, 128, false, &flags));
            assert(flags == (0x10000u | (adhoc ? 2u : 0u)));
        }
    }
    cd[64] = 0; put32(cd + 12, 0);
    assert(roothide_signature_normalized_flags(cd, 128, true, &flags) && flags == 2);
    for (unsigned offset = 1; offset <= 53; ++offset) {
        if (offset == 52 || offset == 53) continue;
        put32(cd + 48, offset);
        assert(!roothide_signature_normalized_flags(cd, 128, true, &flags));
    }
    put32(cd + 48, 128); assert(!roothide_signature_normalized_flags(cd, 128, true, &flags));
    put32(cd + 48, 127); cd[127] = 'X';
    assert(!roothide_signature_normalized_flags(cd, 128, true, &flags));
    put32(cd + 48, 0);
    for (unsigned size = 0; size < 52; ++size)
        assert(!roothide_signature_normalized_flags(cd, size, true, &flags));
    assert(!roothide_signature_normalized_flags(NULL, 128, true, &flags));
    assert(!roothide_signature_normalized_flags(cd, 128, true, NULL));
    put32(cd + 8, 0x20000); put32(cd + 4, 76); put32(cd + 16, 44);
    assert(roothide_signature_normalized_flags(cd, 76, true, &flags) && flags == 2);
    blobStreams[0].size = 76;
    assert(roothide_code_directories_need_normalization(&decoded, true) == 1);
    put32(cd + 8, 0x20200); put32(cd + 4, 44);
    assert(!roothide_signature_normalized_flags(cd, 44, true, &flags));
    reset(2); put32(directory(0) + 12, 2);
    assert(roothide_code_directories_need_normalization(&decoded, true) == 1);
    put32(directory(1) + 12, 2);
    assert(roothide_code_directories_need_normalization(&decoded, true) == 0 && writes == 0);
    blobs[1].type = 0; assert(roothide_code_directories_need_normalization(&decoded, true) == -1);
    reset(1); directory(0)[36] = 255;
    assert(roothide_code_directories_need_normalization(&decoded, true) == -1);
    reset(1); directory(0)[39] = 0;
    assert(roothide_code_directories_need_normalization(&decoded, true) == 1);
    put32(directory(0) + 28, 2);
    assert(roothide_code_directories_need_normalization(&decoded, true) == -1);
}
static void writer_cases(void) {
    uint8_t hash[20], expected[32], original[20];
    reset(2); CC_SHA256(directory(0), 128, expected); memcpy(original, expected, 20);
    assert(ensure_randomized_cdhash_for_slice("Sileo", UINT64_MAX, hash) == 0);
    assert(stream_count == 0 && writes == 5);
    assert(get32(directory(0) + 12) == 2 && get32(directory(1) + 12) == 2);
    CC_SHA256(image, 4096, expected);
    assert(!memcmp(expected, directory(0) + 96, 32) && !memcmp(expected, directory(1) + 96, 32));
    CC_SHA256(directory(0), 128, expected);
    assert(!memcmp(hash, expected, 20) && memcmp(hash, original, 20));
    assert(roothide_code_directories_need_normalization(&decoded, true) == 0);
    // A CMS-free wrapper with both Team ID and ADHOC must lose only ADHOC.
    reset(1); put32(directory(0) + 12, 0x10002); put32(directory(0) + 48, 64);
    memcpy(directory(0) + 64, "TEAM\0", 5);
    assert(ensure_randomized_cdhash_for_slice("TeamID", 0, hash) == 0);
    assert(get32(directory(0) + 12) == 0x10000 && stream_count == 0);
    CC_SHA256(directory(0), 128, expected); assert(!memcmp(hash, expected, 20));
    // A prepared section marker must not hide missing signature flags.
    reset(1); uint64_t marker = brand;
    memcpy(image + 32 + sizeof(struct segment_command_64) + offsetof(struct section_64, segname) + 8, &marker, 8);
    assert(ensure_randomized_cdhash_for_slice("RootHide", 0, hash) == 0);
    assert(writes == 2 && get32(directory(0) + 12) == 2 && stream_count == 0);
    // Invalid alternate metadata must fail before changing jbrand/any directory.
    reset(2); put32(directory(1) + 48, 128);
    assert(ensure_randomized_cdhash_for_slice("RootHide", 0, hash) == -1 && writes == 0 && stream_count == 0);
    for (int failure = 1; failure <= 5; ++failure) {
        reset(2); fail_write = failure;
        assert(ensure_randomized_cdhash_for_slice("RootHide", 0, hash) == -1 && stream_count == 0);
    }
    reset(1); fail_fat = true;
    assert(ensure_randomized_cdhash_for_slice("RootHide", 0, hash) == -1 && stream_count == 0);
    reset(1); fail_hash = true;
    assert(ensure_randomized_cdhash_for_slice("RootHide", 0, hash) == -1 && stream_count == 0);
    reset(1); cms_signed = true;
    assert(ensure_randomized_cdhash_for_slice("CMS", 0, hash) == -1 && writes == 0 && stream_count == 0);
    reset(1); sptm = false;
    assert(ensure_randomized_cdhash_for_slice("iOS16", 0, hash) == 0 && get32(directory(0) + 12) == 0);
}
'''

COLLECTOR_MOCKS = r'''
static bool old_trusted, final_trusted, queued, collected;
static int preparations, preparation_result;
static bool cdhashesContains(uint8_t *hash) { (void)hash; return queued; }
static bool is_cdhash_trustcached(uint8_t *hash) { return hash[0] == 1 ? old_trusted : final_trusted; }
static void cdhashesAdd(uint8_t *hash) { assert(hash[0] == 2); collected = true; }
static int mock_prepare(const char *path, uint64_t offset, void *out) {
    (void)path; (void)offset; ++preparations;
    if (preparation_result) return preparation_result;
    for (CS_DecodedBlob *blob = decoded.firstBlob; blob; blob = blob->next) put32(blob->stream->data + 12, 2);
    ((uint8_t *)out)[0] = 2; return 0;
}
#define ensure_randomized_cdhash_for_slice mock_prepare
static void collector_step(bool *collectionFailed) {
    uint8_t cdhash[20] = {1};
    CS_DecodedSuperBlob *decodedSuperblob = &decoded;
    MachO slice = {0}; MachO *macho = &slice;
    struct { const char *fileSystemRepresentation; } realLoadPath = {"Sileo"};
'''

COLLECTOR_CASES = r'''
}
#undef ensure_randomized_cdhash_for_slice
static void collector_cases(void) {
    for (unsigned trusted = 0; trusted < 2; ++trusted) {
        for (unsigned normalized = 0; normalized < 2; ++normalized) {
            reset(1); put32(directory(0) + 12, normalized ? 2 : 0);
            old_trusted = trusted; final_trusted = false; queued = false; collected = false;
            preparations = 0; preparation_result = 0; bool failed = false;
            collector_step(&failed);
            assert(!failed && preparations == ((!trusted || !normalized) ? 1 : 0));
            assert(collected == (!trusted || !normalized));
            old_trusted = true; queued = false; collected = false; preparations = 0;
            collector_step(&failed); assert(!failed && preparations == 0 && !collected);
        }
    }
    reset(2); put32(directory(0) + 12, 2); old_trusted = true; final_trusted = false;
    preparations = 0; collected = false; bool failed = false;
    collector_step(&failed); assert(!failed && preparations == 1 && collected);
    reset(1); put32(directory(0) + 48, 128); preparations = 0; collected = false;
    collector_step(&failed); assert(failed && preparations == 0 && !collected);
    reset(1); preparation_result = -1; failed = false; collected = false;
    collector_step(&failed); assert(failed && !collected);
    reset(1); preparation_result = 0; final_trusted = true; failed = false; collected = false;
    collector_step(&failed); assert(!failed && !collected);
    reset(1); sptm = false; old_trusted = true; preparations = 0;
    collector_step(&failed); assert(preparations == 0);
}
int main(void) {
    policy_cases(); writer_cases(); collector_cases();
    puts("PASS: TXM flag combinations, bounded Team ID, alternate directories, final hashes, trusted-file repair, no repeated preparation, failure cleanup");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    recdhash = (SOURCE / 'recdhash.m').read_text(encoding='utf-8')
    collector = (SOURCE / 'signatures.m').read_text(encoding='utf-8')
    file_collector = (SOURCE.parent / 'signatures.c').read_text(encoding='utf-8')
    guard = extract(collector, 'if (!cdhashesContains(cdhash))')
    functions = '\n'.join(extract(recdhash, signature) for signature in (
        'Fat* fat_init_for_writing(', 'static bool roothide_is_code_directory_slot(',
        'static bool roothide_read_code_directory(', 'int roothide_code_directories_need_normalization(',
        'int calc_cdhash(', 'MachO* fat_find_slice_by_offset(', 'int ensure_randomized_cdhash_for_slice(',
    ))
    assert 'normalizedFlags != codeDir.flags' in functions
    assert functions.index('roothide_code_directories_need_normalization(decodedSuperblob, usesSPTM)') < functions.index('*rd2 = jbinfo(jbrand)')
    assert functions.index('offsetof(CS_CodeDirectory, flags)') < functions.index('calc_cdhash(newCDBlob')
    file_function = extract(file_collector, 'int file_collect_untrusted_cdhashes(')
    assert 'roothide_code_directories_need_normalization(decodedSuperblob, true)' in file_function
    assert '|| normalization > 0' in file_function and 'if (is_cdhash_trustcached(cdhash)) return;' in file_function
    assert 'test_roothide_txm_signatures.py' in (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    harness = PREFIX + functions + CASES + COLLECTOR_MOCKS + guard + COLLECTOR_CASES
    print('PASS: production directory writer and both trust-collector paths are wired', flush=True)
    if args.check_only:
        print('C/Objective-C runtime harness NOT run (--check-only); TXM/device validation remains required.')
        return
    if sys.platform != 'darwin':
        raise SystemExit('Signature-write harness requires macOS/CommonCrypto; use --check-only elsewhere.')
    with tempfile.TemporaryDirectory(prefix='roothide-txm-') as directory:
        source = Path(directory) / 'test.m'
        binary = Path(directory) / 'test'
        source.write_text(harness, encoding='utf-8')
        subprocess.run(['xcrun', 'clang', '-fblocks', '-Wno-deprecated-declarations',
                        '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        '-I', str(SOURCE), str(source), str(SOURCE / 'signature_policy.c'),
                        '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=20,
                       env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1', 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    main()
