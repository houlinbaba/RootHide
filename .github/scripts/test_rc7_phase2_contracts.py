#!/usr/bin/env python3
"""RC7 iOS 16 phase-2 host regression: respawn error paths and ABI/build contracts.

This exercises the real jailbreakd respawn branch with mocked platform calls. It
is not an on-device jailbreakd, Mach/XPC, dyld or userspace-reboot test.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
read = lambda rel: (ROOT / rel).read_text(encoding="utf-8")

source = read("BaseBin/jailbreakd/src/main.m")
start = source.index("\t\t\tif(unrestrict(pid, proc_patch_dyld, false) != 0) {")
end = source.index("\n\t\t}\n\n\t\tJBLogDebug(\"check in jailbreakd port...\")", start)
real_branch = source[start:end]

header = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#define SIGKILL 9
#define SIGCONT 18
#define JBLogError(...) ((void)0)
typedef int pid_t;
static int unrestrict_fail, patch_enabled, resume_fail;
static int seen_signals[4], signal_count, wait_count;
static int proc_patch_dyld;
static int unrestrict(pid_t pid, int method, bool ignored) {
  (void)pid; (void)method; (void)ignored;
  return unrestrict_fail ? -1 : 0;
}
static bool dyld_patch_enabled(void) {return patch_enabled != 0;}
static int fake_kill(pid_t pid, int sig) {
  (void)pid;
  if (signal_count >= 4) abort();
  seen_signals[signal_count++] = sig;
  return sig == SIGCONT && resume_fail ? -1 : 0;
}
static pid_t fake_waitpid(pid_t pid, int *status, int options) {
  (void)status; (void)options;
  wait_count++;
  return pid;
}
#define kill fake_kill
#define waitpid fake_waitpid
'''
footer = r'''
static void check(int unrestrict_f, int patch, int resume_f, int expected,
                  int nsignals, int first_sig, int second_sig, int waits) {
  unrestrict_fail = unrestrict_f;
  patch_enabled = patch;
  resume_fail = resume_f;
  signal_count = wait_count = 0;
  int rc = exercise(123);
  if (rc != expected || signal_count != nsignals || wait_count != waits ||
      (nsignals > 0 && seen_signals[0] != first_sig) ||
      (nsignals > 1 && seen_signals[1] != second_sig)) {
    fprintf(stderr, "FAIL rc=%d/%d signals=%d/%d waits=%d/%d first=%d second=%d\n",
      rc, expected, signal_count, nsignals, wait_count, waits,
      seen_signals[0], seen_signals[1]);
    exit(1);
  }
}
int main(void) {
  check(1, 1, 0, 5, 1, SIGKILL, 0, 1);            // unrestrict fails
  check(0, 1, 0, 0, 1, SIGCONT, 0, 0);            // resumed child
  check(0, 1, 1, 5, 2, SIGCONT, SIGKILL, 1);     // resume fails
  check(0, 0, 0, 10, 1, SIGKILL, 0, 1);           // fallback stays in parent
  puts("PASS: 4 jailbreakd suspended-child cleanup scenarios");
  return 0;
}
'''
compiler = shutil.which("clang") or shutil.which("cc")
if not compiler:
    raise SystemExit("No clang/cc available to test respawn branch")
with tempfile.TemporaryDirectory() as td:
    test_c = Path(td) / "respawn.c"
    binary = Path(td) / "respawn"
    test_c.write_text(header + "\nstatic int exercise(pid_t pid) {\n" + real_branch + "\nreturn 10;\n}\n" + footer)
    subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(test_c), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# The iOS 16 artifacts are not the same as upstream's multi-version artifacts.
# Verify that the RC7 packager, dyldhook Makefile and runtime selector agree.
dyld_mk = read("BaseBin/dyldhook/Makefile")
base_mk = read("BaseBin/Makefile")
selector = read("BaseBin/libjailbreak/src/basebin_gen.m")
for arch in ("arm64", "arm64e"):
    name = f"dyldhook_merge.{arch}.dylib"
    assert re.search(r"^" + re.escape(name) + r":", dyld_mk, re.M), f"No build rule: {name}"
    assert f"cp dyldhook/{name} .build" in base_mk, f"Not packaged: {name}"
    assert f'@"{name}"' in selector, f"Not selected: {name}"
assert (ROOT / "BaseBin/dyldhook/src/generated/ios16/task.c").is_file()
print("PASS: iOS 16 dyldhook arm64/arm64e build-package-selector consistency")

# Both Mach client and server must share the same action constants, header and
# ABI struct definitions, never copy only one side from official 3.x.
protocol = read("BaseBin/libjailbreak/src/jbserver.h")
client = read("BaseBin/libjailbreak/src/jbclient_mach.c")
server = read("BaseBin/launchdhook/src/jbserver/jbserver_mach.c")
for i, action in enumerate(("CHECKIN", "FORK_FIX", "TRUST_FILE")):
    name = f"JBSERVER_MACH_{action}"
    assert re.search(r"#define\s+" + name + r"\s+" + str(i) + r"\b", protocol)
    assert name in client and name in server, f"Mach client/server mismatch for {name}"
print("PASS: 3 Mach check-in/fork/trust action constants shared")

# The non-upstream RootHide forceDyldPatch setting is an intentional RC7 ABI
# extension and must remain paired across jailbreakd and the client.
server_xpc = read("BaseBin/jailbreakd/src/server.m")
client_xpc = read("BaseBin/libjailbreak/src/roothider/jailbreakd.c")
assert 'xpc_dictionary_get_bool(message, "force-dyld-patch")' in server_xpc
assert 'roothide_patch_proc_ex(pid, forceDyldPatch)' in server_xpc
assert '"force-dyld-patch"' in client_xpc
print("PASS: RC7 forceDyldPatch extension preserved on both XPC ends")
