#!/usr/bin/env python3
"""Regress the WD91 startup error path against extracted production C.

--source-only checks wiring on hosts without a POSIX compiler. The full test
exercises actual file diagnostics and injected runtime-load failures; it does
not simulate iOS service startup or establish device stability.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/systemhook/src"


def extract_function(text, signature):
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise ValueError("unterminated function: " + signature)


def source_checks():
    for path in SOURCE.rglob("*"):
        if path.suffix not in {".c", ".h"}:
            continue
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\b(?:openlog|syslog|closelog)\s*\(", text), path
    header = (SOURCE / "roothider.h").read_text(encoding="utf-8")
    assert "common/runtime_diagnostics.h" in header
    makefile = (SOURCE.parent / "Makefile").read_text(encoding="utf-8")
    assert "src/common/*.c" in makefile  # new implementation is actually linked
    workflow = (ROOT / ".github/workflows/roothide.yml").read_text(encoding="utf-8")
    assert "python3 .github/scripts/test_systemhook_startup_diagnostics.py\n" in workflow
    main = (SOURCE / "main.c").read_text(encoding="utf-8")
    roothider = (SOURCE / "roothider_main.c").read_text(encoding="utf-8")
    for text, signature in [
        (main, "static bool load_required_runtime_dylib("),
        (roothider, "bool roothide_init_with_checkin("),
        (roothider, "bool roothide_init_with_executable("),
    ]:
        function = extract_function(text, signature)
        assert "ROOTHIDE_RUNTIME_DIAGNOSTIC(" in function, signature
        assert "fprintf(stderr" not in function, signature
        assert "return false;" in function, signature
    return main, roothider


FILE_HARNESS = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
static const char *test_log_path;
#define ROOTHIDE_RUNTIME_DIAGNOSTIC_PATH test_log_path
''' + '#include "' + (SOURCE / "common/runtime_diagnostics.c").as_posix() + '"\n' + r'''
static size_t read_file(const char *path, char *out, size_t capacity) {
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    ssize_t length = read(fd, out, capacity - 1);
    assert(length >= 0);
    out[length] = 0;
    close(fd);
    return (size_t)length;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    test_log_path = argv[1];
    char buffer[8192];
    errno = EDOM;
    roothide_runtime_diagnostic("load failed: path=%s error=%s", "/usr/lib/roothidepatch.dylib", "missing dependency");
    assert(errno == EDOM);
    size_t first_length = read_file(test_log_path, buffer, sizeof(buffer));
    assert(strstr(buffer, "[RootHideRuntime "));
    assert(strstr(buffer, "pid="));
    assert(strstr(buffer, "roothidepatch.dylib error=missing dependency\n"));
    char long_error[4096];
    memset(long_error, 'x', sizeof(long_error) - 1);
    long_error[sizeof(long_error) - 1] = 0;
    errno = ERANGE;
    roothide_runtime_diagnostic("%s", long_error);
    assert(errno == ERANGE);
    size_t total_length = read_file(test_log_path, buffer, sizeof(buffer));
    assert(total_length > first_length && total_length - first_length <= 2047);
    assert(buffer[total_length - 1] == '\n');
    errno = EDOM;
    roothide_runtime_diagnostic(NULL);
    assert(errno == EDOM);
    assert(read_file(test_log_path, buffer, sizeof(buffer)) == total_length);

    /* A substituted symlink must not overwrite its target. */
    assert(unlink(test_log_path) == 0);
    int fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, "sentinel", 8) == 8);
    close(fd);
    assert(symlink(argv[2], test_log_path) == 0);
    errno = EDOM;
    roothide_runtime_diagnostic("must not follow symlink");
    assert(errno == EDOM);
    assert(read_file(argv[2], buffer, sizeof(buffer)) == 8);
    assert(!strcmp(buffer, "sentinel"));

    /* A hard link is a regular file, but is not a private log destination. */
    assert(unlink(test_log_path) == 0);
    assert(link(argv[2], test_log_path) == 0);
    errno = EDOM;
    roothide_runtime_diagnostic("must not append through a hard link");
    assert(errno == EDOM);
    assert(read_file(argv[2], buffer, sizeof(buffer)) == 8);
    assert(!strcmp(buffer, "sentinel"));

    /* No reader is present: this would hang without O_NONBLOCK. */
    assert(unlink(test_log_path) == 0);
    assert(mkfifo(test_log_path, 0600) == 0);
    errno = EDOM;
    roothide_runtime_diagnostic("must not wait for a FIFO reader");
    assert(errno == EDOM);
    assert(unlink(test_log_path) == 0);
    assert(mkdir(test_log_path, 0700) == 0);
    errno = EDOM;
    roothide_runtime_diagnostic("unwritable log must not change result");
    assert(errno == EDOM);
    assert(rmdir(test_log_path) == 0);
    puts("PASS: runtime diagnostics append, truncation, errno, link and FIFO failures");
    return 0;
}
'''

LOAD_HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
static const char *test_patch_path;
static bool fail_load;
static int load_calls, diagnostic_calls;
static char diagnostic[1024];
static bool isRemovableBundlePath(const char *path) { (void)path; return false; }
static int __sysctl(void) { return 0; }
static int __sysctl_hook(void) { return 0; }
static int __sysctlbyname(void) { return 0; }
static int __sysctlbyname_hook(void) { return 0; }
static void litehook_hook_function(void *a, void *b) { (void)a; (void)b; }
static bool string_has_suffix(const char *path, const char *suffix) { (void)path; (void)suffix; return false; }
static void loadPathHook(void) { assert(!"unexpected Dopamine-only path"); }
static void *test_dlopen(const char *path, int flags) {
    assert(path && flags == 2);
    ++load_calls;
    return fail_load ? NULL : (void *)0x1234;
}
static const char *test_dlerror(void) { return "injected missing dependency"; }
static void test_diagnostic(const char *format, ...) {
    ++diagnostic_calls;
    va_list args;
    va_start(args, format);
    vsnprintf(diagnostic, sizeof(diagnostic), format, args);
    va_end(args);
}
#define __builtin_available(...) (false)
#define JBROOT_PATH(path) test_patch_path
#define RTLD_NOW 2
#define dlopen test_dlopen
#define dlerror test_dlerror
#define ROOTHIDE_RUNTIME_DIAGNOSTIC(...) test_diagnostic(__VA_ARGS__)
/* The old production error path fails this negative control at runtime. */
#define SYSLOG(...) assert(!"startup error reached a service logger")
'''

LOAD_CASES = r'''
int main(void) {
    test_patch_path = "/var/jb/usr/lib/roothidepatch.dylib";
    fail_load = true;
    assert(!roothide_init_with_executable("/usr/libexec/xpcproxy"));
    assert(load_calls == 1 && diagnostic_calls == 1);
    assert(strstr(diagnostic, test_patch_path));
    assert(strstr(diagnostic, "injected missing dependency"));
    diagnostic_calls = 0;
    test_patch_path = NULL;
    assert(!roothide_init_with_executable("/usr/libexec/xpcproxy"));
    assert(load_calls == 1 && diagnostic_calls == 1);
    assert(strstr(diagnostic, "path resolution failed"));
    diagnostic_calls = 0;
    test_patch_path = "/var/jb/usr/lib/roothidepatch.dylib";
    fail_load = false;
    assert(roothide_init_with_executable("/usr/libexec/xpcproxy"));
    assert(load_calls == 2 && diagnostic_calls == 0);
    assert(!load_required_runtime_dylib("forkfix", NULL));
    assert(diagnostic_calls == 1);
    diagnostic_calls = 0;
    fail_load = true;
    assert(!load_required_runtime_dylib("forkfix", "/basebin/forkfix.dylib"));
    assert(diagnostic_calls == 1 && strstr(diagnostic, "injected missing dependency"));
    diagnostic_calls = 0;
    fail_load = false;
    assert(load_required_runtime_dylib("forkfix", "/basebin/forkfix.dylib"));
    assert(diagnostic_calls == 0);
    puts("PASS: extracted startup load failures return without service logging");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    main_source, roothider = source_checks()
    print("PASS: systemhook startup service-logging guard and CI wiring")
    if args.source_only:
        print("SOURCE_ONLY: C execution and iOS validation were not performed")
        return
    if os.environ.get("CC"):
        compiler = shlex.split(os.environ["CC"])
    elif sys.platform == "darwin":
        compiler = ["xcrun", "clang"]
    else:
        compiler = [shutil.which("clang") or shutil.which("gcc") or "clang"]
    # Darwin hides O_NOFOLLOW under a POSIX-only feature profile. Exercise
    # the same Darwin interfaces available to the production Apple build.
    feature_flags = (["-D_DARWIN_C_SOURCE"] if sys.platform == "darwin"
                     else ["-D_POSIX_C_SOURCE=200809L"])
    with tempfile.TemporaryDirectory(prefix="systemhook_startup_") as tmp:
        tmp = Path(tmp)
        cases = {
            "diagnostics": FILE_HARNESS,
            "load_failures": LOAD_HARNESS
            + extract_function(main_source, "static bool load_required_runtime_dylib(")
            + "\n" + extract_function(roothider, "bool roothide_init_with_executable(")
            + LOAD_CASES,
        }
        for name, content in cases.items():
            source = tmp / (name + ".c")
            binary = tmp / name
            source.write_text(content, encoding="utf-8")
            subprocess.run(compiler + feature_flags + ["-std=c11", "-Wall", "-Wextra", "-Werror",
                           "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                           str(source), "-o", str(binary)], check=True)
            command = [str(binary)]
            if name == "diagnostics":
                command += [str(tmp / "runtime.log"), str(tmp / "sentinel")]
            subprocess.run(command, check=True, timeout=20)


if __name__ == "__main__":
    main()
