#!/usr/bin/env python3
"""Host-side extraction tests of RC7 hookd startup and Mach check-in failure paths."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROVIDER = ROOT / 'BaseBin/launchdhook/src/hookd_provider.c'
HELPER = ROOT / 'BaseBin/hookd/src/main.c'


def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    assert start >= 0, f'missing function: {signature}'
    begin = source.find('{', start)
    depth = 0
    for i in range(begin, len(source)):
        if source[i] == '{': depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return source[start:i+1]
    raise AssertionError(f'failed extracting {signature}')


src = PROVIDER.read_text()
function = extract_function(src, 'int hookd_start(')
child = HELPER.read_text()
assert re.search(r'if\s*\(\s*!registeredPorts\s*\|\|\s*registeredPortsCount\s*<\s*3\s*\)', child)
assert child.index('registeredPortsCount < 3') < child.index('registeredPorts[2]')
assert re.search(r'if\s*\(\s*checkinPort\s*==\s*MACH_PORT_NULL\s*\)\s*\{[^}]*vm_deallocate\(', child, re.S)

mock_c = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

typedef int pid_t;
typedef int mach_port_t;
typedef int kern_return_t;
typedef int posix_spawnattr_t;
typedef struct { unsigned int msgh_bits, msgh_size; mach_port_t msgh_remote_port, msgh_local_port; unsigned int msgh_voucher_port, msgh_id; } mach_msg_header_t;
#define MACH_PORT_NULL 0
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_PORT_RIGHT_SEND 2
#define MACH_MSG_TYPE_MAKE_SEND 3
#define MACH_RCV_MSG 4
#define KERN_SUCCESS 0
#define KERN_INVALID_RIGHT 17
#define MAX_TRAILER_SIZE 64
#define MACH_PORT_VALID(port) ((port) > 0)
#define JBROOT_PATH(path) (path)

static int fail_step, port_destroy_count, attr_destroy_count, spawned_count, killed_count, msg_destroy_count, retained_count, checked_size_count;
static int failure(int s) { return fail_step == s ? 71+s : 0; }
static int mach_task_self(void) { return 1; }
static kern_return_t mach_port_allocate(int task, int right, mach_port_t *out) { (void)task; (void)right; if (failure(1)) return failure(1); *out=100; return 0; }
static kern_return_t mach_port_insert_right(int task, mach_port_t p, mach_port_t q, int disp) { (void)task; (void)p; (void)q; (void)disp; return failure(2); }
static kern_return_t mach_port_destroy(int task, mach_port_t p) { (void)task; assert(p==100); port_destroy_count++; return 0; }
static int posix_spawnattr_init(posix_spawnattr_t *attr) { *attr=50; return failure(3); }
static int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *attr, mach_port_t ports[], uint32_t count) { assert(*attr==50 && count==3 && ports[2]==100); return failure(4); }
static int posix_spawnattr_destroy(posix_spawnattr_t *attr) { assert(*attr==50); attr_destroy_count++; return 0; }
static int posix_spawn(pid_t *pid, const char *path, void *actions, posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
    (void)actions; assert(*attr==50 && argv[0]==path && envp[0]); *pid=123; spawned_count++; return failure(5);
}
static int mach_msg(mach_msg_header_t *hdr, int opts, unsigned int snd, unsigned int rcv, mach_port_t port, unsigned int timeout, int notify) {
    (void)snd; (void)timeout; (void)notify; assert(opts==MACH_RCV_MSG && port==100);
    assert(rcv>=sizeof(*hdr)+MAX_TRAILER_SIZE);
    checked_size_count++;
    if (failure(6)) return failure(6);
    memset((char*)hdr + sizeof(*hdr), 0xA5, MAX_TRAILER_SIZE);
    hdr->msgh_size=sizeof(*hdr);
    hdr->msgh_remote_port=fail_step==7?MACH_PORT_NULL:404;
    return 0;
}
static kern_return_t mach_port_mod_refs(int task, mach_port_t p, int right, int refs) { (void)task; assert(p==404 && right==MACH_PORT_RIGHT_SEND && refs==1); retained_count++; return failure(8); }
static void mach_msg_destroy(mach_msg_header_t *hdr) { assert(hdr); msg_destroy_count++; }
static int kill(pid_t pid, int sig) { assert(pid==123 && sig==SIGKILL); killed_count++; return 0; }

INSERT_FUNCTION

static void reset_counts(int step) { fail_step=step; port_destroy_count=attr_destroy_count=spawned_count=killed_count=msg_destroy_count=retained_count=checked_size_count=0; }
static void test_one(int step) {
    reset_counts(step);
    pid_t pid=-1;
    mach_port_t port=-1;
    int r=hookd_start(&pid,&port);
    assert(r==(step==0?0:(step==7?KERN_INVALID_RIGHT:71+step)));
    assert(port==(step==0?404:MACH_PORT_NULL));
    assert(port_destroy_count==(step==1?0:1));
    assert(attr_destroy_count==(step>=1&&step<=3?0:1));
    assert(spawned_count==(step>=1&&step<=4?0:1));
    assert(killed_count==(step>=6?1:0));
    assert(checked_size_count==(step==0||step>=6?1:0));
    assert(msg_destroy_count==(step==0||step==7||step==8?1:0));
    assert(retained_count==(step==0||step==8?1:0));
}
int main(void) {
    for(int step=0; step<=8; step++) { test_one(step); }
    reset_counts(0);
    assert(hookd_start(NULL,NULL)==EINVAL);
    assert(port_destroy_count==0);
    puts("10 Mach check-in mock scenarios PASS");
    return 0;
}
'''.replace('INSERT_FUNCTION', function)

with tempfile.TemporaryDirectory(prefix='rc7-hookd-p3-') as work:
    c_file = Path(work) / 'hookd_checkin.c'
    exe_file = Path(work) / 'hookd_checkin'
    c_file.write_text(mock_c)
    comp = subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(c_file),'-o',str(exe_file)], capture_output=True,text=True)
    assert comp.returncode == 0, comp.stderr
    run = subprocess.run([str(exe_file)], capture_output=True, text=True)
    assert run.returncode == 0, f'{run.stdout}\n{run.stderr}'
    print(run.stdout.strip())
print('hookd registered-port count and invalid-port guard PASS')

# The real server parsing loop must tolerate truncated or inconsistent payloads.
server = HELPER.read_text()
chunk = server.split('// Apply hooks', 1)[1].split('// Apply fixups', 1)[0]
chunk = re.sub(r'\bint64_t \*hookResults = NULL;\s*uint32_t hookCount = 0;', '', chunk, count=1)
parse_c = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef unsigned long vm_address_t;
typedef unsigned long vm_size_t;
struct hookd_encoded_hook { vm_address_t address; vm_size_t dataSize; uint8_t data[]; };
struct payload { int clientPid; int taskPortInClient; } req = {1,2};
static struct payload *msg = &req;
static int applied;
static int apply_hook(int task, int target, vm_address_t addr, void *data, vm_size_t sz) {
  (void)task; (void)target; (void)addr; (void)data; (void)sz; applied++; return 19;
}
static void run_test(uint32_t hs, uint32_t len, int expected) {
  uint8_t raw[128] = {0};
  struct hookd_encoded_hook header = { .address=9, .dataSize=len };
  memcpy(raw, &header, sizeof(header));
  uint8_t *hooksStart=raw;
  uint32_t hooksSize=hs;
  int clientTaskPort=3;
  int64_t *hookResults=NULL;
  uint32_t hookCount=0;
  applied=0;
PAYLOAD_LOOP
  assert(hookCount==(unsigned int)expected);
  assert(applied==expected);
  if (hookResults) { assert(hookResults[0]==19); free(hookResults); }
  return;
deny:
  assert(!"unexpected allocation failure");
}
int main(void) {
  run_test((uint32_t)sizeof(struct hookd_encoded_hook)-1, 0, 0);
  run_test((uint32_t)sizeof(struct hookd_encoded_hook), 0, 1);
  run_test((uint32_t)sizeof(struct hookd_encoded_hook), 50, 0);
  run_test((uint32_t)sizeof(struct hookd_encoded_hook)+4, 4, 1);
  puts("4 hook payload boundary cases PASS");
  return 0;
}
'''.replace('PAYLOAD_LOOP', chunk)
with tempfile.TemporaryDirectory(prefix='rc7-hookd-parser-') as work:
    c_file = Path(work) / 'hook_parser.c'
    exe_file = Path(work) / 'hook_parser'
    c_file.write_text(parse_c)
    comp = subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c_file),'-o',str(exe_file)],capture_output=True,text=True)
    assert comp.returncode == 0, comp.stderr
    run = subprocess.run([str(exe_file)],capture_output=True,text=True)
    assert run.returncode == 0, f'{run.stdout}\n{run.stderr}'
    print(run.stdout.strip())
assert 'free(reply);' in server and server.index('free(reply);') > server.index('mach_msg_send(&reply->hdr)')
print('hookd Mach reply release guard PASS')
