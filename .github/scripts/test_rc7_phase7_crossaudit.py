#!/usr/bin/env python3
"""RC7 Phase7 compilation-target contract + protected-source snapshot check.

No iOS build here. Protects user custom UI/Issuer/Glass/Resources and manager payloads
from unintended modifications relative to the initial uploaded RC7 snapshot.
"""
from pathlib import Path
import hashlib, json
root = Path(__file__).resolve().parents[2]
base = root/'BaseBin'
launchmk=(base/'launchdhook/Makefile').read_text()
sysmk=(base/'systemhook/Makefile').read_text()
assert '../systemhook/src/common.c' in launchmk, 'missing launchdhook common compilation'
assert 'src/common/*.c' in sysmk, 'missing systemhook common compilation'
assert '../systemhook/src/common/envbuf.c' in launchmk, 'missing envbuf in launchdhook'
assert 'src/common/*.c' in sysmk, 'missing envbuf in systemhook'
launch_common=(base/'systemhook/src/common.c').read_text()
sys_common=(base/'systemhook/src/common/common.c').read_text()
provider=(base/'launchdhook/src/roothider.m').read_text()
for source,label in ((launch_common,'launchdhook common'),(sys_common,'systemhook common')):
    assert 'if (envp && !envc) return ENOMEM;' in source, label+': unchecked copy allocation'
    assert 'bool updated = envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES"' in source, label+': unchecked insert'
    assert 'if (!updated)' in source, label+': failed insert not handled'
    assert 'if (!newLibraryInsert)' in source, label+': unchecked allocation'
    assert 'if (r == ENOMEM)' in source, label+': execve errno contract missing'
assert 'envPrepared = envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");' in provider
assert 'envPrepared = envbuf_setenv(&envc, "SPINLOCK_FIX_DISABLED", "1");' in provider
assert 'if (!envPrepared)' in provider and 'posix_spawnattr_setflags(attrp, flags);' in provider
assert 'return ENOMEM;' in provider, 'launchd failed environment injection must abort cleanly'
print('PASS: two real compiled common.c targets and launchd environment guards')
manifest=json.loads((root/'.github/scripts/rc7_phase7_protection_manifest.json').read_text())['protected_sha256']
paths={key:root/key for key in manifest}
for rel,f in paths.items():
    assert f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest()==manifest[rel],f'protected file changed: {rel}'
current=set()
for subtree in ('Application','Packages','.pictures'):
    for f in (root/subtree).rglob('*'):
        if f.is_file() and '__pycache__' not in f.parts and not f.is_symlink():
            rel=str(f.relative_to(root))
            if rel!='Application/Dopamine/Jailbreak/DOBootstrapper.m':current.add(rel)
assert current==set(manifest),f'protected file set changed: added={sorted(current-set(manifest))[:10]}, removed={sorted(set(manifest)-current)[:10]}'
print(f'PASS: {len(manifest)} protected files remain byte-for-byte intact')
