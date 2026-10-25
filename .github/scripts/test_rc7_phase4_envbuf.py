#!/usr/bin/env python3
"""Compile production envbuf.c under host sanitizers and test OOM paths."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
script = Path(__file__).with_name("rc7_phase4_envbuf_harness.c")
include = root / "BaseBin/systemhook/src/common"
source = (include / "common.c").read_text()
assert "if (envp && !envc) return ENOMEM;" in source
assert 'bool inserted = envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES"' in source
assert 'bool updated = envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES"' in source
assert "errno = ENOMEM;" in source
assert '#include "envbuf.h"' in source
assert "src/common/*.c" in (root / "BaseBin/systemhook/Makefile").read_text()
posthook = (root / "BaseBin/systemhook/src/roothider_main.c").read_text()
assert "bool envPrepared = !envp || envc != NULL;" in posthook
assert 'envPrepared = envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");' in posthook
assert "if (patch_exec) jbdSpawnExecCancel(path);" in posthook
assert "olderr = ENOMEM;" in posthook
compiler = shutil.which("clang")
if not compiler:
    raise SystemExit("FAIL: clang not installed")
with tempfile.TemporaryDirectory(prefix="rc7-phase4-") as tmp:
    exe = Path(tmp) / "envbuf-test"
    subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I", str(include),
                    str(script), "-o", str(exe)], check=True)
    # Darwin ASan does not support LeakSanitizer/detect_leaks. Keep ASan/UBSan active.
    asan_options = "halt_on_error=1"
    if sys.platform.startswith("linux"):
        asan_options += ":detect_leaks=1"
    subprocess.run([str(exe)], env={**os.environ, "ASAN_OPTIONS": asan_options}, check=True)
print("PASS production source and caller contract checks")
