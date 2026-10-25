#!/usr/bin/env python3
"""Compile *unmodified extracted functions* from RC7 trustcache.c with POSIX I/O mocks.
Only the includes / external dependencies are stubbed. No Apple SDK or kernel simulation.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap

root = Path(__file__).resolve().parents[2]
source = (root / 'BaseBin/libjailbreak/src/trustcache.c').read_text()


def extract(start, end):
    assert source.count(start) == 1, start
    piece = source.split(start, 1)[1].split(end, 1)[0]
    assert piece.endswith('\n\n'), (start, end)
    return start + piece


functions = ''.join((
    extract('void _trustcache_file_init(', '// iOS 16:'),
    extract('int _trustcache_file_sort_entry_comparator_v1(', 'bool _is_jb_trustcache('),
    extract('int jb_trustcache_add_cdhashes(', 'int jb_trustcache_add_entry('),
    extract('int trustcache_file_build_from_cdhashes(', 'bool trustcache_contains_cdhash('),
))
# There is unrelated code between comparator/sort and _is_jb_trustcache? The extracted block
# stops just before _is_jb_trustcache, so it is precisely two tested helper functions.

preamble = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CS_CDHASH_LEN 20
typedef uint8_t cdhash_t[CS_CDHASH_LEN];
typedef uint8_t uuid_t[16];
typedef struct trustcache_entry_v1 { cdhash_t hash; uint8_t hash_type; uint8_t flags; } __attribute__((packed)) trustcache_entry_v1;
typedef struct s_trustcache_file_v1 { uint32_t version; uuid_t uuid; uint32_t length; trustcache_entry_v1 entries[]; } __attribute__((packed)) trustcache_file_v1;
void uuid_generate(uuid_t uuid) { memset(uuid, 0x42, 16); }
static int injected_add_result, add_calls;
int jb_trustcache_add_entries(trustcache_entry_v1 *entries, uint32_t count) {
  add_calls++;
  assert(entries && count == 3);
  assert(entries[0].hash[0]==3 && entries[1].hash[0]==1 && entries[2].hash[0]==2);
  assert(entries[0].hash_type==1 && entries[1].hash_type==1 && entries[2].flags==0);
  return injected_add_result;
}

static int fail_alloc, fail_stat, eintr_once, short_reads, eof_after_bytes = -1, read_error;
static int close_calls, open_calls, read_calls;
static size_t read_so_far;
static void *test_malloc(size_t n) { if (fail_alloc) { errno=ENOMEM; return NULL; } return malloc(n); }
static int test_open(const char *p, int f) { open_calls++; return open(p,f); }
static int test_fstat(int fd, struct stat *s) { if (fail_stat) { errno=EIO; return -1; } return fstat(fd,s); }
static ssize_t test_read(int fd, void *buf, size_t len) {
  read_calls++;
  if (eintr_once) { eintr_once=0; errno=EINTR; return -1; }
  if (read_error) { errno=EIO; return -1; }
  if (eof_after_bytes >= 0 && read_so_far >= (size_t)eof_after_bytes) return 0;
  if (short_reads && len > 5) len=5;
  if (eof_after_bytes >= 0 && len > (size_t)eof_after_bytes - read_so_far) len=(size_t)eof_after_bytes - read_so_far;
  ssize_t n=read(fd,buf,len);
  if (n>0) read_so_far+=(size_t)n;
  return n;
}
static int test_close(int fd) { close_calls++; return close(fd); }
#define malloc test_malloc
#define open test_open
#define fstat test_fstat
#define read test_read
#define close test_close
'''
postamble = r'''
#undef malloc
#undef open
#undef fstat
#undef read
#undef close
static void reset_mocks(void) {
  fail_alloc=fail_stat=eintr_once=short_reads=read_error=0;
  eof_after_bytes=-1; close_calls=open_calls=read_calls=0; read_so_far=0;
}
static void put_file(char *name, const void *data, size_t length) {
  int fd=mkstemp(name); assert(fd>=0);
  size_t done=0;
  while (done<length) { ssize_t n=write(fd,(const char*)data+done,length-done); assert(n>0); done+=(size_t)n; }
  assert(close(fd)==0);
}
static trustcache_file_v1 *new_tc(uint32_t count) {
  trustcache_file_v1 *v=calloc(1, sizeof(*v) + count * sizeof(trustcache_entry_v1));
  assert(v); v->version=1; v->length=count;
  for (uint32_t i=0;i<count;i++) { v->entries[i].hash[0]=(uint8_t)(i+1); v->entries[i].hash_type=2; }
  return v;
}
static void test_path_valid(void) {
  trustcache_file_v1 *input=new_tc(3);
  char name[]="/tmp/rc7_tc_valid_XXXXXX";
  size_t sz=sizeof(*input)+3*sizeof(trustcache_entry_v1);
  put_file(name,input,sz);
  trustcache_file_v1 *out=(void*)0x1234;
  reset_mocks(); assert(trustcache_file_build_from_path(name,&out)==0);
  assert(out&&out->length==3&&out->entries[2].hash[0]==3);
  assert(open_calls==1&&close_calls==1); free(out);
  reset_mocks(); short_reads=1; out=NULL;
  assert(trustcache_file_build_from_path(name,&out)==0);
  assert(read_calls>3 && close_calls==1); free(out);
  reset_mocks(); eintr_once=1; out=NULL;
  assert(trustcache_file_build_from_path(name,&out)==0);
  assert(read_calls>=2 && close_calls==1); free(out);
  reset_mocks(); fail_stat=1; out=(void*)0x1234;
  assert(trustcache_file_build_from_path(name,&out)<0);
  assert(!out && close_calls==1);
  reset_mocks(); fail_alloc=1; out=(void*)0x1234;
  assert(trustcache_file_build_from_path(name,&out)<0);
  assert(!out && close_calls==1);
  reset_mocks(); read_error=1; out=(void*)0x1234;
  assert(trustcache_file_build_from_path(name,&out)<0);
  assert(!out && close_calls==1);
  reset_mocks(); eof_after_bytes=8; out=(void*)0x1234;
  assert(trustcache_file_build_from_path(name,&out)<0);
  assert(!out && close_calls==1);
  reset_mocks(); out=NULL;
  assert(trustcache_file_build_from_path(name,NULL)<0);
  assert(trustcache_file_build_from_path(NULL,&out)<0);
  assert(open_calls==0);
  unlink(name); free(input);
}
static void test_path_malformed(void) {
  char too_small[]="/tmp/rc7_tc_tiny_XXXXXX";
  uint8_t junk[8]={0}; put_file(too_small,junk,sizeof(junk));
  trustcache_file_v1 *out=(void*)0x1234;
  reset_mocks(); assert(trustcache_file_build_from_path(too_small,&out)<0);
  assert(!out && close_calls==1); unlink(too_small);

  char nonmultiple[]="/tmp/rc7_tc_odd_XXXXXX";
  uint8_t odd[sizeof(trustcache_file_v1)+1]={0}; put_file(nonmultiple,odd,sizeof(odd));
  reset_mocks(); out=(void*)0x1234;
  assert(trustcache_file_build_from_path(nonmultiple,&out)<0);
  assert(!out && close_calls==1); unlink(nonmultiple);

  trustcache_file_v1 *in=new_tc(2);
  char mismatch[]="/tmp/rc7_tc_badcount_XXXXXX";
  in->length=1;
  put_file(mismatch,in,sizeof(*in)+2*sizeof(trustcache_entry_v1));
  reset_mocks(); out=(void*)0x1234;
  assert(trustcache_file_build_from_path(mismatch,&out)<0);
  assert(!out && close_calls==1); unlink(mismatch); free(in);

  reset_mocks(); out=(void*)0x1234;
  assert(trustcache_file_build_from_path("/nonexistent/rc7/tc",&out)<0);
  assert(!out && close_calls==0);
}
static void test_cdhash_add(void) {
  cdhash_t hashes[3]={{3},{1},{2}};
  reset_mocks(); add_calls=0; injected_add_result=0;
  assert(jb_trustcache_add_cdhashes(hashes,3)==0 && add_calls==1);
  reset_mocks(); add_calls=0; injected_add_result=-7;
  assert(jb_trustcache_add_cdhashes(hashes,3)==-7 && add_calls==1);
  reset_mocks(); add_calls=0; fail_alloc=1;
  assert(jb_trustcache_add_cdhashes(hashes,3)<0 && add_calls==0);
  reset_mocks(); assert(jb_trustcache_add_cdhashes(NULL,3)<0);
  assert(jb_trustcache_add_cdhashes(NULL,0)==0);
}
static void test_cdhashes(void) {
  cdhash_t hashes[3] = {{3}, {1}, {2}};
  trustcache_file_v1 *out=(void*)0x1234;
  reset_mocks();
  assert(trustcache_file_build_from_cdhashes(hashes,3,&out)==0);
  assert(out&&out->version==1&&out->length==3);
  assert(out->entries[0].hash[0]==1 && out->entries[1].hash[0]==2 && out->entries[2].hash[0]==3);
  assert(out->entries[2].hash_type==2 && out->entries[2].flags==0); free(out);
  reset_mocks(); fail_alloc=1; out=(void*)0x1234;
  assert(trustcache_file_build_from_cdhashes(hashes,3,&out)<0);
  assert(!out);
  reset_mocks();
  assert(trustcache_file_build_from_cdhashes(hashes,0,&out)<0);
  assert(trustcache_file_build_from_cdhashes(NULL,3,&out)<0);
  assert(trustcache_file_build_from_cdhashes(hashes,3,NULL)<0);
}
int main(void) {
  test_path_valid(); test_path_malformed(); test_cdhashes(); test_cdhash_add();
  puts("PASS: 23 trustcache input/error-path cases from actual source");
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='rc7trust_') as td:
    harness = Path(td) / 'test.c'
    binary = Path(td) / 'test'
    harness.write_text(preamble + '\n' + functions + '\n' + postamble)
    clang = shutil.which('clang')
    if not clang:
        raise RuntimeError('clang required')
    compile_cmd = [clang, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                   str(harness), '-o', str(binary)]
    subprocess.run(compile_cmd, check=True, capture_output=True, text=True)
    # Darwin ASan does not support LeakSanitizer/detect_leaks. Keep ASan/UBSan active.
    asan_options = 'halt_on_error=1'
    if sys.platform.startswith('linux'):
        asan_options += ':detect_leaks=1'
    proc = subprocess.run([str(binary)], check=True, capture_output=True, text=True,
                          env={**os.environ, 'ASAN_OPTIONS': asan_options})
    print(proc.stdout.strip())
