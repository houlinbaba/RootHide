#!/usr/bin/env python3
"""Run production Developer Mode code against fake kernel/OID state.

Reproduces the raw AMFI query returning launch_env_logging after the RootHide
OID swap, and checks certificate policy, handoff iteration, and failure gates.
This cannot validate TXM writes or SpringBoard behavior on a device.
"""

import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import tempfile

from test_launchd_injection import extract

ROOT = Path(__file__).resolve().parents[2]

PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct sysctl_oid_list { struct sysctl_oid *first; };
#define SLIST_ENTRY(type) struct { struct type *sle_next; }
#define UNSIGN_PTR(value) (value)
#define JBLogDebug(...) ((void)0)
#define jbinfo(name) (gSystemInfo.jailbreakInfo.name)
#define ksymbol(name) (symbol_##name)
#define ksymbol_txm(name) (symbol_##name)
#define SYS_sysctlbyname 274
#define syscall mock_syscall

static uint64_t symbol_developer_mode_enabled, symbol_txm_developer_mode_storage;
static uint64_t symbol_developer_mode_status, symbol_launch_env_logging;
static uint8_t mode_storage;
static uint64_t kernel_pointer;
static int reads, writes, queries, fail_read, fail_pointer, fail_write, drop_write;
static int query_errno, query_size, query_value;
static bool ios16_or_newer;
static bool roothide_is_ios16_or_newer(void) { return ios16_or_newer; }
static void roothide_stage_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void roothide_stage_log(const char *format, ...) { (void)format; }

static int kreadbuf(uint64_t address, void *output, size_t size) {
    if (address == (uint64_t)&kernel_pointer && fail_pointer) return EIO;
    if (address == (uint64_t)&mode_storage && ++reads == fail_read) return EIO;
    memcpy(output, (const void *)(uintptr_t)address, size);
    return 0;
}
static uint64_t kread64(uint64_t address) {
    uint64_t value = 0;
    assert(kreadbuf(address, &value, sizeof(value)) == 0);
    return value;
}
static int kwrite8(uint64_t address, uint8_t value) {
    assert(address == (uint64_t)&mode_storage && value == 1);
    ++writes;
    if (fail_write) return EIO;
    if (!drop_write) memcpy((void *)(uintptr_t)address, &value, sizeof(value));
    return 0;
}
static void kwrite32(uint64_t address, uint32_t value) {
    memcpy((void *)(uintptr_t)address, &value, sizeof(value));
}
static void kwrite64(uint64_t address, uint64_t value) {
    memcpy((void *)(uintptr_t)address, &value, sizeof(value));
}
static long mock_syscall(int number, ...);
'''

CASES = r'''
static struct sysctl_oid_list dev_parent, launch_parent;
static struct sysctl_oid dev_oid, launch_oid;
static char dev_name[64] = "developer_mode_status";
static char launch_name[64] = "launch_env_logging";

// Fake raw lookup: a named OID retains its handler/data when RootHide swaps
// its name/number with another OID, exactly as the production function does.
static int raw_status(void) {
    struct sysctl_oid *lists[] = {dev_parent.first, launch_parent.first};
    for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); ++i) {
        for (struct sysctl_oid *oid = lists[i]; oid; oid = oid->oid_link.sle_next) {
            if (strcmp(oid->oid_name, dev_name) == 0) {
                return oid == &dev_oid ? mode_storage : 0; // logging defaults off
            }
        }
    }
    return -1;
}
static long mock_syscall(int number, ...) {
    assert(number == SYS_sysctlbyname);
    ++queries;
    va_list args;
    va_start(args, number);
    const char *name = va_arg(args, const char *);
    size_t length = va_arg(args, size_t);
    int *value = va_arg(args, int *);
    size_t *size = va_arg(args, size_t *);
    assert(va_arg(args, void *) == NULL && va_arg(args, int) == 0);
    va_end(args);
    assert(strcmp(name, "security.mac.amfi.developer_mode_status") == 0);
    assert(length == strlen(name) && *size == sizeof(*value));
    if (query_errno) { errno = query_errno; return -1; }
    *value = query_value < 0 ? raw_status() : query_value;
    if (query_size >= 0) *size = (size_t)query_size;
    return 0;
}
static void reset(bool txm) {
    memset(&gSystemInfo, 0, sizeof(gSystemInfo));
    memset(&dev_oid, 0, sizeof(dev_oid));
    memset(&launch_oid, 0, sizeof(launch_oid));
    dev_parent.first = &dev_oid; launch_parent.first = &launch_oid;
    dev_oid.oid_parent = &dev_parent; launch_oid.oid_parent = &launch_parent;
    dev_oid.oid_name = dev_name; launch_oid.oid_name = launch_name;
    dev_oid.oid_number = 3; launch_oid.oid_number = 7;
    symbol_developer_mode_status = (uint64_t)&dev_oid.oid_name;
    symbol_launch_env_logging = (uint64_t)&launch_oid.oid_name;
    kernel_pointer = (uint64_t)&mode_storage;
    symbol_developer_mode_enabled = txm ? 0 : (uint64_t)&kernel_pointer;
    symbol_txm_developer_mode_storage = txm ? kernel_pointer : 0;
    mode_storage = 0;
    reads = writes = queries = fail_read = fail_pointer = fail_write = drop_write = 0;
    query_errno = 0; query_size = query_value = -1;
    ios16_or_newer = true;
}
static void handoff(void) {
    struct system_info saved = {0};
#define SAVE_INFO(ctx, name) ctx.name = gSystemInfo.name
    JAILBREAK_INFO_ITERATE(saved, SAVE_INFO);
#undef SAVE_INFO
    memset(&gSystemInfo, 0, sizeof(gSystemInfo));
#define RESTORE_INFO(ctx, name) gSystemInfo.name = ctx.name
    JAILBREAK_INFO_ITERATE(saved, RESTORE_INFO);
#undef RESTORE_INFO
}
int main(void) {
    for (int txm = 0; txm < 2; ++txm) {
        reset(txm); jbinfo(preserveDeveloperMode) = true;
        assert(enableDeveloperMode() == 0 && mode_storage == 1 && writes == 1 && queries == 1);
        assert(!shouldHideDeveloperMode());
        handoff(); // policy survives the same field iteration used by XPC
        assert(jbinfo(preserveDeveloperMode) && !shouldHideDeveloperMode());
        if (shouldHideDeveloperMode()) hideDeveloperMode();
        assert(raw_status() == 1); // uninjected certificate App launch check
        assert(enableDeveloperMode() == 0 && writes == 1); // no unnecessary rewrite

        reset(txm); // legacy TrollStore policy still hides the OID
        assert(enableDeveloperMode() == 0 && shouldHideDeveloperMode());
        handoff(); assert(!jbinfo(preserveDeveloperMode) && shouldHideDeveloperMode());
        hideDeveloperMode();
        assert(mode_storage == 1 && raw_status() == 0); // reproduces reported gate
        assert(enableDeveloperMode() == 0); // TrollStore permits the hidden query
        jbinfo(preserveDeveloperMode) = true;
        assert(enableDeveloperMode() != 0); // certificate launch still needs raw status

        // Device feedback: A16/17.0, TrollStore, TXM before=after=1, raw=0.
        // Do not require an OID swap to reproduce this observed combination.
        reset(txm); mode_storage = 1; query_value = 0;
        assert(enableDeveloperMode() == 0 && writes == 0 && queries == 1);
        assert(reads == 2 && !jbinfo(preserveDeveloperMode));

        reset(txm); fail_read = 1;
        assert(enableDeveloperMode() != 0 && writes == 0 && queries == 0);
        reset(txm); fail_write = 1;
        assert(enableDeveloperMode() != 0 && queries == 0);
        reset(txm); drop_write = 1;
        assert(enableDeveloperMode() != 0 && mode_storage == 0 && queries == 0);
        reset(txm); fail_read = 2;
        assert(enableDeveloperMode() != 0 && queries == 0);
        // Raw status is a launch prerequisite for certificate installs and
        // diagnostic-only for TrollStore. Byte/write failures above stay fatal.
        for (int certificate = 0; certificate < 2; ++certificate) {
            reset(txm); jbinfo(preserveDeveloperMode) = certificate;
            query_errno = ENOENT;
            assert((enableDeveloperMode() != 0) == (bool)certificate && queries == 1);
            reset(txm); jbinfo(preserveDeveloperMode) = certificate;
            query_size = 1;
            assert((enableDeveloperMode() != 0) == (bool)certificate);
            reset(txm); jbinfo(preserveDeveloperMode) = certificate;
            query_value = 0;
            assert((enableDeveloperMode() != 0) == (bool)certificate);
        }
        reset(txm); mode_storage = 1; fail_write = 1;
        assert(enableDeveloperMode() == 0 && writes == 0 && queries == 1);
    }
    reset(false); fail_pointer = 1;
    assert(enableDeveloperMode() != 0 && writes == 0);
    reset(false); kernel_pointer = 0;
    assert(enableDeveloperMode() == ENOENT && writes == 0);
    reset(false); symbol_developer_mode_enabled = symbol_txm_developer_mode_storage = 0;
    assert(enableDeveloperMode() == ENOENT && writes == 0);
    reset(false); ios16_or_newer = false;
    assert(!shouldHideDeveloperMode());
    puts("PASS: TrollStore byte=1/raw=0 feedback, certificate launch gates, OID/handoff policy, kernel/TXM failures");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    app = (ROOT / 'Application/Dopamine/Jailbreak/DOJailbreaker.m').read_text(encoding='utf-8')
    launchd = (ROOT / 'BaseBin/launchdhook/src/roothider.m').read_text(encoding='utf-8')
    common = (ROOT / 'BaseBin/libjailbreak/src/roothider/common.m').read_text(encoding='utf-8')
    info = (ROOT / 'BaseBin/libjailbreak/src/info.h').read_text(encoding='utf-8')
    # Verify these production helpers are still used by the entry points.
    method = extract(app, '- (NSError *)ensureDevModeEnabled')
    assert 'jbinfo(preserveDeveloperMode) = ![[DOEnvironmentManager sharedManager] isInstalledThroughTrollStore];' in method
    assert 'int result = enableDeveloperMode();' in method and 'if (result != 0)' in method
    assert 'code:JBErrorCodeFailedDeveloperMode' in method
    postinit = extract(launchd, 'void roothide_launchd_postinit(')
    assert 'if (shouldHideDeveloperMode())\n\t\t{\n\t\t\thideDeveloperMode();' in postinit
    iteration = info[info.index('#define JAILBREAK_INFO_ITERATE'):info.index('#define JAILBREAK_SETTINGS_ITERATE')]
    production = (extract(info, 'struct system_info {') + ';\nstatic struct system_info gSystemInfo;\n'
                  + iteration + extract(common, 'struct sysctl_oid {') + ';\n'
                  + extract(common, 'void oid_remove(') + '\n' + extract(common, 'void oid_insert(') + '\n'
                  + extract(common, 'void hideDeveloperMode(') + '\n'
                  + extract(launchd, 'static bool shouldHideDeveloperMode(') + '\n'
                  + extract(app, 'static int enableDeveloperMode(') + '\n')
    scratch = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='developer-mode-')
    with scratch as directory:
        temp = Path(directory)
        source = temp / 'devmode.c'
        binary = temp / ('devmode.exe' if args.zig else 'devmode')
        source.write_text(PREFIX + production + CASES, encoding='utf-8')
        compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['clang']
        sanitizer = [] if args.zig else ['-fsanitize=address,undefined']
        subprocess.run(compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror'] + sanitizer
                       + [str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=20)


if __name__ == '__main__':
    main()
