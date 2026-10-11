#!/usr/bin/env python3
"""Verify slow settings services cannot block cell getters or overwrite edits."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = ROOT / 'Application/Dopamine/UI/Settings'
CLIENT = ROOT / 'BaseBin/libjailbreak/src'


def method(text, signature):
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 0
    for pos in range(opening, len(text)):
        depth += (text[pos] == '{') - (text[pos] == '}')
        if not depth:
            return text[start:pos + 1]
    raise ValueError(signature)


HARNESS = r'''
#import "DORuntimeSettingsSnapshot.h"
#include <assert.h>
#include <stdio.h>
static void pumpUntil(BOOL (^done)(void)) {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:3];
    while (!done() && deadline.timeIntervalSinceNow > 0) {
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.005]];
    }
    assert(done());
}
int main(void) {
    @autoreleasepool {
        dispatch_semaphore_t started = dispatch_semaphore_create(0);
        dispatch_semaphore_t release = dispatch_semaphore_create(0);
        __block NSUInteger calls = 0, completions = 0;
        DORuntimeSettingsSnapshot *snapshot = [[DORuntimeSettingsSnapshot alloc] initWithLoader:^{
            assert(!NSThread.isMainThread);
            calls++;
            dispatch_semaphore_signal(started);
            assert(dispatch_semaphore_wait(release, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0);
            return @{@"appJITEnabled": @NO, @"jetsamMultiplier": @8};
        }];
        [snapshot refreshWithCompletion:^{ assert(NSThread.isMainThread); completions++; }];
        assert(dispatch_semaphore_wait(started, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) == 0);
        for (NSUInteger i = 0; i < 20; i++) {
            assert(![snapshot runtimeValueForKey:@"appJITEnabled"]);
            [snapshot refreshWithCompletion:^{ assert(!"duplicate pending refresh"); }];
        }
        [snapshot setRuntimeValue:@YES forKey:@"appJITEnabled"];
        assert([snapshot runtimeValueForKey:@"appJITEnabled"].boolValue);
        dispatch_semaphore_signal(release);
        pumpUntil(^BOOL { return completions == 1; });
        assert(calls == 1);
        assert([snapshot runtimeValueForKey:@"appJITEnabled"].boolValue);
        assert([snapshot runtimeValueForKey:@"jetsamMultiplier"].intValue == 8);
        [snapshot refreshWithCompletion:^{ assert(!"scrolling bypassed cooldown"); }];
        assert(dispatch_semaphore_wait(started, DISPATCH_TIME_NOW) != 0);

        // Failed reads remain unknown so the caller can use configured defaults.
        __block BOOL failedDone = NO;
        DORuntimeSettingsSnapshot *failed = [[DORuntimeSettingsSnapshot alloc] initWithLoader:^{ return (NSDictionary *)nil; }];
        [failed refreshWithCompletion:^{ failedDone = YES; }];
        pumpUntil(^BOOL { return failedDone; });
        assert(![failed runtimeValueForKey:@"dyldPatchEnabled"]);
        puts("PASS: delayed background read, memory-only getters, one pending refresh, edit preservation, cooldown, failed-read fallback");
    }
    return 0;
}
'''

C_HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { int type; bool boolean; double number; } test_object;
typedef test_object *xpc_object_t;
#define XPC_TYPE_BOOL 1
#define XPC_TYPE_DOUBLE 2
#define JBS_DOMAIN_ROOTHIDE 10
#define JBS_ROOTHIDE_DYLD_PATCH_ENABLED_GET 11
static test_object setting = {XPC_TYPE_BOOL, false, 4.5}, reply;
static int status, calls, releases;
static bool missing_value, missing_reply;
static int jbclient_jbsettings_get(const char *key, xpc_object_t *valueOut) {
    assert(key && valueOut);
    calls++;
    if (!missing_value) *valueOut = &setting;
    return status;
}
static int xpc_get_type(xpc_object_t object) { assert(object); return object->type; }
static bool xpc_bool_get_value(xpc_object_t object) { assert(object->type == XPC_TYPE_BOOL); return object->boolean; }
static double xpc_double_get_value(xpc_object_t object) { assert(object->type == XPC_TYPE_DOUBLE); return object->number; }
static void xpc_release(xpc_object_t object) { assert(object); releases++; }
static xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t args) {
    assert(domain == JBS_DOMAIN_ROOTHIDE && action == JBS_ROOTHIDE_DYLD_PATCH_ENABLED_GET && !args);
    calls++;
    return missing_reply ? NULL : &reply;
}
static int64_t xpc_dictionary_get_int64(xpc_object_t object, const char *key) {
    assert(object == &reply && !strcmp(key, "result"));
    return status;
}
static xpc_object_t xpc_dictionary_get_value(xpc_object_t object, const char *key) {
    assert(object == &reply && !strcmp(key, "enabled"));
    return missing_value ? NULL : &setting;
}
'''

C_CASES = r'''
int main(void) {
    bool enabled = true;
    double multiplier = 9;
    assert(jbclient_jbsettings_get_bool_checked(NULL, &enabled) == -1);
    assert(jbclient_jbsettings_get_bool_checked("key", NULL) == -1);
    assert(jbclient_jbsettings_get_double_checked(NULL, &multiplier) == -1);
    assert(jbclient_jbsettings_get_double_checked("key", NULL) == -1);
    assert(jbclient_dyld_patch_enabled_get(NULL) == -1);
    assert(calls == 0);
    assert(jbclient_jbsettings_get_bool_checked("key", &enabled) == 0 && !enabled);
    assert(releases == 1);
    missing_value = true;
    enabled = true;
    assert(jbclient_jbsettings_get_bool_checked("key", &enabled) == -1 && enabled);
    assert(jbclient_jbsettings_get_double_checked("key", &multiplier) == -1 && multiplier == 9);
    assert(releases == 1);
    missing_value = false;
    status = -5;
    assert(jbclient_jbsettings_get_bool_checked("key", &enabled) == -5 && enabled);
    assert(jbclient_jbsettings_get_double_checked("key", &multiplier) == -5 && multiplier == 9);
    assert(releases == 3);
    status = 0;
    assert(jbclient_jbsettings_get_double_checked("key", &multiplier) == -1 && multiplier == 9);
    setting.type = XPC_TYPE_DOUBLE;
    assert(jbclient_jbsettings_get_bool_checked("key", &enabled) == -1 && enabled);
    assert(jbclient_jbsettings_get_double_checked("key", &multiplier) == 0 && multiplier == 4.5);
    assert(releases == 6);
    assert(jbclient_dyld_patch_enabled_get(&enabled) == -1 && enabled);
    missing_value = true;
    assert(jbclient_dyld_patch_enabled_get(&enabled) == -1 && enabled);
    missing_value = false;
    status = -6;
    assert(jbclient_dyld_patch_enabled_get(&enabled) == -6 && enabled);
    status = 0;
    setting.type = XPC_TYPE_BOOL;
    assert(jbclient_dyld_patch_enabled_get(&enabled) == 0 && !enabled);
    assert(releases == 10);
    missing_reply = true;
    enabled = true;
    assert(jbclient_dyld_patch_enabled_get(&enabled) == -1 && enabled);
    assert(releases == 10);
    puts("PASS: checked service reads, missing/wrong values, retained-object release, no output mutation on failure");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    source = (SETTINGS / 'DOSettingsController.m').read_text(encoding='utf-8')
    for name in ('readIDownloadEnabled', 'readAppJITEnabled', 'readJetsamMultiplier', 'readDyldPatchEnabled'):
        body = method(source, f'- (id){name}:')
        assert 'readRuntimePreferenceValue:specifier' in body
        for forbidden in ('jbclient_', '.isIDownloadEnabled', 'runAsRoot', 'runUnsandboxed'):
            assert forbidden not in body, (name, forbidden)
    loader = method(source, '- (DORuntimeSettingsSnapshot *)runtimeSettingsSnapshot')
    assert 'initWithLoader:' in loader
    assert 'runAsRoot' not in loader and 'runUnsandboxed' not in loader
    for api in ('jbclient_jbsettings_get_bool_checked', 'jbclient_jbsettings_get_double_checked', 'jbclient_dyld_patch_enabled_get'):
        assert api in loader
        assert api in (CLIENT / 'jbclient_xpc.h').read_text(encoding='utf-8')
    assert 'xpc_release' not in loader  # C client owns XPC objects, UI receives primitives.
    clients = (CLIENT / 'jbclient_xpc.c').read_text(encoding='utf-8')
    roothide = (CLIENT / 'jbclient_roothide.c').read_text(encoding='utf-8')
    checked = '\n'.join((method(clients, 'int jbclient_jbsettings_get_bool_checked('),
                         method(clients, 'int jbclient_jbsettings_get_double_checked('),
                         method(roothide, 'int jbclient_dyld_patch_enabled_get(')))
    getter = method(source, '- (id)readRuntimePreferenceValue:')
    assert '?: [self readPreferenceValue:specifier]' in getter
    assert 'test_settings_runtime_snapshot.py' in (ROOT / '.github/workflows/roothide.yml').read_text(encoding='utf-8')
    print('PASS: settings cell getters use cached values, service refresh changes no process credentials', flush=True)
    if args.check_only:
        print('Foundation runtime harness NOT run (--check-only); Apple/device verification remains required.')
        return
    if sys.platform != 'darwin':
        raise SystemExit('Foundation runtime harness requires macOS; use --check-only elsewhere.')
    with tempfile.TemporaryDirectory(prefix='settings-snapshot-') as directory:
        client_source = Path(directory) / 'client.c'
        client_binary = Path(directory) / 'client'
        client_source.write_text(C_HARNESS + checked + C_CASES, encoding='utf-8')
        subprocess.run(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(client_source), '-o', str(client_binary)], check=True)
        subprocess.run([str(client_binary)], check=True, timeout=10)
        source_path = Path(directory) / 'test.m'
        binary = Path(directory) / 'test'
        source_path.write_text(HARNESS, encoding='utf-8')
        subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-fblocks', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-framework', 'Foundation', '-I', str(SETTINGS), str(source_path), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15,
                       env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'})


if __name__ == '__main__':
    main()
