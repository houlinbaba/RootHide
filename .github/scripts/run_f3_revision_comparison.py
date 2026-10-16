#!/usr/bin/env python3
"""Archive exact before/after F3 comparisons without disguising remaining FAIL."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zig', type=Path)
    p.add_argument('--workdir', type=Path, required=True)
    a = p.parse_args()
    a.workdir.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, revision, expectation in [('audit','39c2d31','baseline'),
                                         ('before','5337b52','deadline'),
                                         ('corrected',None,'correction')]:
        folder = a.workdir / name
        folder.mkdir(exist_ok=True)
        command = [sys.executable,str(ROOT / '.github/scripts/test_boomerang_timing.py'),
                   '--workdir',str(folder),'--output',str(folder / 'results.json'),'--expect',expectation]
        if revision: command += ['--revision',revision]
        if a.zig: command += ['--zig',str(a.zig.resolve())]
        run = subprocess.run(command,capture_output=True,text=True,encoding='utf-8',timeout=90)
        (folder / 'command.json').write_text(json.dumps(dict(command=command,exit_code=run.returncode,
            stdout=run.stdout,stderr=run.stderr),indent=2),encoding='utf-8')
        if not (folder / 'results.json').exists():
            print(run.stdout,run.stderr)
            raise RuntimeError(name + ' did not produce complete observations')
        results[name] = json.loads((folder / 'results.json').read_text(encoding='utf-8'))
        assert run.returncode == 1 and results[name]['acceptance_pass'] is False
    # Unchanged correct contract: each ordinary eventual handoff must finish.
    for mode in (0,1,2,7,8,9):
        assert not results['audit']['cases'][mode]['observation']['unsafe']
        assert not results['corrected']['cases'][mode]['observation']['unsafe']
        event = results['corrected']['cases'][mode]['observation']
        assert event['resumes'] == 1 and event['helper_result'] == 0 and not event['target_paused']
    for mode in (2,9):
        assert results['before']['cases'][mode]['observation']['unsafe']
    # Resume failure and denied cleanup are not repaired by removing a timer.
    for version in results.values():
        assert version['cases'][6]['observation']['unsafe']
        assert version['cases'][19]['observation']['unsafe']
    summary = dict(correction_verified=True,F3='FAIL',comparison=results,
        limits='Independent host fixtures. Same inputs except production revision. No target reachability or device acceptance. Cleanup scenarios 8/9 now inject callback failure too so baseline reaches the same cleanup path without a timer.')
    (a.workdir / 'comparison.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print('Regression corrected across both callers; F3 remains FAIL. Counterexamples audit/before/corrected:',
          [r['counterexamples'] for r in results.values()])

if __name__ == '__main__':
    main()
