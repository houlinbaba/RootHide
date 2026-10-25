#!/usr/bin/env python3
"""Host-side behavior regression for official RootHide release-28 RC7 backports.

Uses the actual apply_hook C body with Mach API stubs; not an iOS device test.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "BaseBin/hookd/src/main.c").read_text()
body = source.split("int apply_hook(", 1)[1].split("\nint apply_fixup(", 1)[0]
body = "int apply_hook(" + body
assert "kern_return_t restoreKr = vm_protect(" in body
assert "return kr;" in body

header = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
typedef int mach_port_t;
typedef int kern_return_t;
typedef uintptr_t vm_address_t;
typedef uintptr_t vm_offset_t;
typedef size_t vm_size_t;
typedef unsigned int mach_msg_type_number_t;
#define KERN_SUCCESS 0
#define MACH_PORT_VALID(p) ((p) > 0)
#define MACH_PORT_RIGHT_SEND 17
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_PROT_COPY 8
static int protect_write_ret, protect_exec_ret, write_ret;
static int protect_calls, write_calls, ref_calls;
static mach_port_t mach_task_self(void) {return 1;}
static mach_port_t extract_task_port(mach_port_t a, mach_port_t b) {(void)a;(void)b;return 23;}
static int mach_port_mod_refs(mach_port_t self, mach_port_t port, int right, int count) {
  (void)self;(void)port;(void)right;
  if (count != -1) abort();
  ref_calls++;
  return 0;
}
static int vm_protect(mach_port_t port, vm_address_t at, vm_size_t size, bool setmax, int prot) {
  (void)port;(void)at;(void)size;(void)setmax;
  protect_calls++;
  return (prot & VM_PROT_WRITE) ? protect_write_ret : protect_exec_ret;
}
static int vm_write(mach_port_t port, vm_address_t at, vm_offset_t data, mach_msg_type_number_t size) {
  (void)port;(void)at;(void)data;(void)size;
  write_calls++;
  return write_ret;
}
'''

footer = r'''
static void run_case(int first, int written, int restored, int expected, int expected_protect, int expected_write) {
  protect_write_ret=first;write_ret=written;protect_exec_ret=restored;
  protect_calls=write_calls=ref_calls=0;
  const char data[]="abc";
  int ret=apply_hook(1, 2, 1024, data, 3);
  if (ret != expected || protect_calls != expected_protect || write_calls != expected_write || ref_calls != 1) {
    fprintf(stderr,"FAIL: result=%d expected=%d protect=%d/%d write=%d/%d refs=%d\n",
      ret,expected,protect_calls,expected_protect,write_calls,expected_write,ref_calls);
    exit(1);
  }
}
int main(void) {
  run_case(7,0,0,7,1,0);          // writable permission fails
  run_case(0,13,0,13,2,1);        // write fails, restore succeeds
  run_case(0,0,42,42,2,1);        // restore fails: real Mach code returned
  run_case(0,13,42,42,2,1);       // restore failure takes precedence
  run_case(0,0,0,0,2,1);          // success
  puts("PASS: 5 hookd Mach error-propagation cases");
  return 0;
}
'''

compiler = shutil.which("clang") or shutil.which("cc")
if not compiler:
    raise SystemExit("No C compiler: cannot execute hookd regression harness")
with tempfile.TemporaryDirectory() as td:
    harness = Path(td) / "hookd_test.c"
    exe = Path(td) / "hookd_test"
    harness.write_text(header + body + footer)
    subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

update = (ROOT / "BaseBin/launchdhook/src/update.m").read_text()
assert 'randomizeAndLoadBasebinTrustcache(tmpBasebinPath.fileSystemRepresentation)' in update
assert 'removeItemAtPath:trustcachePath' not in update, "Must preserve basebin.tc for future updates"
assert re.search(r'fileExistsAtPath:trustcachePath\]\)\s*\{\s*\[\[NSFileManager defaultManager\] removeItemAtPath:tmpExtractionPath error:nil\];\s*return 3;', update)
print("PASS: BaseBin trustcache preserved and missing-trustcache extraction cleaned up (source guard)")
