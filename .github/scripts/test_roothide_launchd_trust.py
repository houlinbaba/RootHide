#!/usr/bin/env python3
"""Regress launchd's local trust call separately from the audited XPC entry."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / 'BaseBin/launchdhook/src/jbserver'


def extract(text, signature):
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == '{':
            depth += 1
        elif text[pos] == '}':
            depth -= 1
            if not depth:
                return text[start:pos + 1]
    raise ValueError(signature)


PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { int pid; } audit_token_t;
typedef void *xpc_object_t;
static int audit_token_to_pid(audit_token_t token) { return token.pid; }
static bool blacklisted, no_process_path;
static bool isBlacklistedToken(audit_token_t *token) { (void)token; return blacklisted; }
static const char *proc_get_path(int pid, void *buffer) {
    (void)pid; (void)buffer;
    return no_process_path ? NULL : "/usr/bin/client";
}
static void fake_log(const char *format, ...) { (void)format; }
#define JBLogError(...) fake_log(__VA_ARGS__)
static int collect_calls, collect_result;
static const char *seen_path, *seen_image, *seen_executable, *seen_working;
static xpc_object_t seen_archs;
static int trust_macho_recurse(const char *path, const char *image, const char *executable,
                              const char *working, xpc_object_t archs) {
    ++collect_calls;
    seen_path = path; seen_image = image; seen_executable = executable;
    seen_working = working; seen_archs = archs;
    return collect_result;
}
'''

CASES = r'''
int main(void) {
    // Real launchd callback -> correctly declared local wrapper -> recursive collector.
    const char *path = "/private/var/containers/Bundle/Application/.jbroot-0011223344556677/Applications/Sileo.app/Sileo";
    assert(roothide_launchd_trust_executable(path) == 0 && collect_calls == 1);
    assert(seen_path == path && seen_image == NULL && seen_executable == path);
    assert(!strcmp(seen_working, "/") && seen_archs == NULL);
    collect_result = 73;
    assert(roothide_launchd_trust_executable(path) == 73 && collect_calls == 2);
    assert(roothide_launchd_trust_executable(NULL) == -1);
    assert(roothide_launchd_trust_executable("") == -1);
    assert(roothide_launchd_trust_executable("relative/Sileo") == -1);
    char oversized[PATH_MAX + 1];
    memset(oversized, 'x', sizeof(oversized)); oversized[0] = '/'; oversized[PATH_MAX] = 0;
    assert(roothide_launchd_trust_executable(oversized) == -1 && collect_calls == 2);

    // The external action still requires a real eligible caller token.
    audit_token_t token = {.pid = 0};
    assert(roothide_trust_executable_recurse(NULL, path, "/", NULL) == -1);
    assert(roothide_trust_executable_recurse(&token, path, "/", NULL) == -1);
    token.pid = 1;
    assert(roothide_trust_executable_recurse(&token, path, "/", NULL) == -1);
    token.pid = 42; blacklisted = true;
    assert(roothide_trust_executable_recurse(&token, path, "/", NULL) == -1);
    blacklisted = false; no_process_path = true;
    assert(roothide_trust_executable_recurse(&token, path, "/", NULL) == -1);
    no_process_path = false;
    assert(roothide_trust_executable_recurse(&token, path, "relative", NULL) == -1);
    assert(collect_calls == 2);
    collect_result = 0;
    xpc_object_t archs = (void *)(uintptr_t)0x1234;
    assert(roothide_trust_executable_recurse(&token, path, "/work", archs) == 0);
    assert(collect_calls == 3 && seen_path == path && seen_image == NULL && seen_executable == path);
    assert(!strcmp(seen_working, "/work") && seen_archs == archs);
    puts("PASS: launchd preserves executable/collector arguments and errors; XPC audit-token and path checks remain enforced");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    server = (SERVER / 'jbdomain_roothide.c').read_text(encoding='utf-8')
    launchd = (SERVER.parent / 'roothider.m').read_text(encoding='utf-8')
    assert '#include "jbdomain_roothide.h"' in server
    assert '#include "jbserver/jbdomain_roothide.h"' in launchd
    assert 'return roothide_trust_executable_recurse(path, "/", NULL)' not in launchd
    assert 'int roothide_trust_executable_recurse(' not in launchd
    assert '.handler = roothide_trust_executable_recurse' in server
    assert '.handler = roothide_trust_executable_for_launchd' not in server
    collector = (ROOT / 'BaseBin/libjailbreak/src/roothider/signatures.m').read_text(encoding='utf-8')
    assert 'ensure_jbroot_symlink(realLoadPath.fileSystemRepresentation)' in collector
    assert 'test_roothide_launchd_trust.py' in (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    functions = '\n'.join(extract(server, sig) for sig in (
        'static bool roothide_privileged_action_allowed(',
        'static bool roothide_path_argument_valid(',
        'int roothide_trust_executable_for_launchd(',
        'static int roothide_trust_executable_recurse(',
    ))
    functions += '\n' + extract(launchd, 'int roothide_launchd_trust_executable(')
    print('PASS: shared declaration, separate local entry, audited action-table wiring', flush=True)
    if args.check_only:
        print('Extracted C harness NOT run (--check-only); Apple/device verification remains required.')
        return
    compiler = (shlex.split(os.environ['CC']) if os.environ.get('CC') else
                ['xcrun', 'clang'] if sys.platform == 'darwin' else
                [shutil.which('clang') or shutil.which('gcc') or 'cc'])
    with tempfile.TemporaryDirectory(prefix='roothide-launchd-trust-') as directory:
        source = Path(directory) / 'test.c'
        binary = Path(directory) / 'test'
        header = '#include "' + (SERVER / 'jbdomain_roothide.h').as_posix() + '"\n'
        source.write_text(PREFIX + header + functions + CASES, encoding='utf-8')
        subprocess.run(compiler + ['-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra', '-Werror',
                                  '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=20)
    print('Scope: real extracted callbacks/guards with a mock collector; on-device link/trust behavior is not simulated.')


if __name__ == '__main__':
    main()
