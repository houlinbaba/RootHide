#!/usr/bin/env python3
"""Local evidence capture for the deadline correction; no remote/device writes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'AI工作记录_新版/证据/2026-10-16_007_期限回归纠正与Apple构建'

def main():
    raw = OUT / 'raw'
    raw.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8',
               ZIG_GLOBAL_CACHE_DIR=str(ROOT / '.build-tools/zig-cache'),
               ZIG_LOCAL_CACHE_DIR=str(ROOT / '.build-tools/zig-local-cache'))
    zig = str(ROOT / '.build-tools/zig/ziglang/zig.exe')
    cases = [
        ('comparison', ['run_f3_revision_comparison.py','--workdir',str(ROOT / '.build-tools/task007/comparison')],0,True),
        ('correction', ['test_unrestrict_contract.py','--regression-correction','--mutations','--darwin-headers'],0,True),
        ('full-f3-contract', ['test_unrestrict_contract.py'],1,True),
        ('D1', ['test_privilege_first_failure.py','--mutations'],0,True),
        ('credentials', ['test_roothide_credentials.py'],0,True),
        ('dyld-metadata', ['test_dyld_metadata.py'],0,True),
        ('policy-default', ['check_candidate_policy.py','--require-distributable'],1,False),
        ('policy-research', ['check_candidate_policy.py','--research'],0,False),
    ]
    for name,args,expected,compiler in cases:
        work = ROOT / '.build-tools/task007' / name
        work.mkdir(parents=True,exist_ok=True)
        command = [sys.executable,str(ROOT / '.github/scripts' / args[0])] + args[1:]
        if compiler: command += ['--zig',zig]
        if name not in ['comparison','policy-default','policy-research']:
            command += ['--workdir',str(work)]
        if name in ['correction','full-f3-contract','D1']:
            command += ['--output',str(raw / (name+'-results.json'))]
        run = subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',timeout=240)
        (raw / (name+'.json')).write_text(json.dumps(dict(command=command,exit_code=run.returncode,
            expected_exit_code=expected,stdout=run.stdout,stderr=run.stderr),ensure_ascii=False,indent=2),encoding='utf-8')
        print(name+': exit='+str(run.returncode)+' expected='+str(expected),flush=True)
        if run.returncode != expected:
            print(run.stdout,run.stderr,flush=True)
            raise RuntimeError(name)
        if name == 'comparison':
            for source in (ROOT / '.build-tools/task007/comparison').rglob('*.json'):
                dest = raw / 'comparison' / source.relative_to(ROOT / '.build-tools/task007/comparison')
                dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,dest)
    git = ['git','-c','safe.directory='+ROOT.as_posix()]
    files = subprocess.check_output(git+['diff','--name-only','39c2d31'],cwd=ROOT).decode().splitlines()
    files += ['docs/review/F3-handoff-correction-20261016.md','docs/review/candidate-status.json',
              '.github/scripts/check_candidate_policy.py','.github/scripts/check_d1_apple_components.py',
              '.github/scripts/run_f3_revision_comparison.py','.github/scripts/record_task007.py']
    hashes = {}
    for name in sorted(set(files)):
        path = ROOT / name
        if not path.is_file(): continue
        dest = OUT / 'tested-sources' / name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,dest)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = dict(head_before=subprocess.check_output(git+['rev-parse','HEAD'],cwd=ROOT).decode().strip(),
        baseline='39c2d31',provenance='independently rebuilt',input_sha256=hashes,
        classification='compile-research',F3='FAIL',F1='FAIL',device_operations=False)
    (OUT / 'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    for name,args in [('correction.diff',['diff']),('relative-audit.diff',['diff','39c2d31'])]:
        (OUT / name).write_bytes(subprocess.check_output(git+args,cwd=ROOT))

if __name__ == '__main__': main()
