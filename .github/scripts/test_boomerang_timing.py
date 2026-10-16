#!/usr/bin/env python3
"""Execute actual old launchd sender/hook and helper main against virtual time.

Default exit 1 means a cross-component safety counterexample remains. This is
not a passing repair gate. Mach, primitives, signals, SETEXEC and queues are
substitutes; pthreads and production control flows run on the host.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from test_unrestrict_contract import extract

ROOT = Path(__file__).resolve().parents[2]
MODES = {0:'normal',1:'DONE-update-9.8s',2:'DONE-update-11s',3:'helper-exits-before-DONE',
         4:'helper-stalls-before-DONE',5:'helper-exits-after-DONE',6:'paused-resume-fails',
         7:'helper-start-delayed-9s',8:'callback-finishes-late',9:'late-preparation-crosses-deadline'}
PARENT_MODES = ['normal','pause-9.8s','pause-crosses-10s','pause-after-10s','query-fails',
                'callback-fails','resume-fails','callback-finishes-20s-late','kill-pending','kill-denied']


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zig',type=Path)
    p.add_argument('--workdir',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--revision',help='Read all production inputs from this Git revision (fixtures remain current)')
    p.add_argument('--expect',choices=['baseline','deadline','correction'],default='correction')
    p.add_argument('--mutant',choices=['parent-no-cleanup','parent-ignore-resume'])
    a=p.parse_args()
    inputs={}
    def read(path):
        if a.revision:
            source=subprocess.check_output(['git','-c','safe.directory='+ROOT.as_posix(),'show',a.revision+':'+path],cwd=ROOT).decode('utf-8')
        else:
            source=(ROOT/path).read_text(encoding='utf-8')
        inputs[path]=hashlib.sha256(source.encode('utf-8')).hexdigest()
        return source
    sender=read('BaseBin/launchdhook/src/boomerang.c')
    helper=extract(read('BaseBin/boomerang/src/main.c'),'int main(')
    helper=helper.replace('int main(', 'static int helper_entry(',1)
    hook=extract(read('BaseBin/launchdhook/src/spawn_hook.c'),'int __posix_spawn_hook(')
    stop=hook.index('\n#if LOG_PROCESS_LAUNCHES',hook.index('return __posix_spawn_orig_wrapper'))
    hook=hook[:stop]+'\nreturn 1234;\n}\n'
    common=extract(read('BaseBin/libjailbreak/src/roothider/common.m'),'int unrestrict(')
    production='\n'.join([common,helper,extract(sender,'static void terminateFailedBoomerang('),
                           extract(sender,'int boomerang_stashPrimitives('),hook])
    fixture=(Path(__file__).parent/'fixtures/boomerang_timing.c').read_text(encoding='utf-8')
    source=a.workdir.resolve()/'timing.c'
    program=a.workdir.resolve()/('timing.exe' if sys.platform=='win32' else 'timing')
    source.write_text(fixture.replace('/* PRODUCTION */',production),encoding='utf-8')
    cc=[str(a.zig.resolve()),'cc'] if a.zig else ['cc']
    subprocess.run(cc+['-std=gnu11','-fblocks','-pthread','-Wall','-Wextra','-Werror',
                      '-Wno-unused-function','-Wno-unused-parameter','-Wno-unused-variable',str(source),'-o',str(program)],check=True)
    cases=[]
    for mode,name in MODES.items():
        r=subprocess.run([str(program),str(mode)],capture_output=True,text=True,timeout=10)
        if r.returncode:
            print(r.stdout,r.stderr,flush=True)
            raise RuntimeError(f'harness failed for {name}: exit={r.returncode}')
        event=json.loads(r.stdout)
        expected_unsafe=(2,5,6,9) if a.expect=='deadline' else (6,)
        assert event['unsafe']==(mode in expected_unsafe), (name,event)
        assert not event['old_receive_live'] and not event['helper_receive_live'], (name,event)
        if mode in (2,5) and a.expect=='deadline':
            assert event['setexec_with_dead_helper'] and event['registered_helper_slot'] and not event['resumes']
        if mode in (3,4):
            assert not event['setexec'] and event['old_result']!=0
        cases.append(dict(name=name,observation=event,stdout=r.stdout,stderr=r.stderr))
        print(name+': '+r.stdout.strip(),flush=True)
    daemon=read('BaseBin/jailbreakd/src/main.m')
    branch=extract(daemon,'if(getenv("RESPAWN_REQUIRED"))')
    branch=branch[branch.index('{')+1:-1]
    if a.mutant=='parent-no-cleanup':
        branch=branch.replace('terminateRespawnedJailbreakdChild(pid);','/* deliberately removed */')
    if a.mutant=='parent-ignore-resume':
        branch=branch.replace('if (kill(pid, SIGCONT) != 0)', 'if (kill(pid, SIGCONT) == 777)')
    production='\n'.join([common,extract(daemon,'static void scheduleRespawnedJailbreakdChildReap('),
        extract(daemon,'static void terminateRespawnedJailbreakdChild('),
        extract(daemon,'static int initializeRespawnedJailbreakdAttributes('),
        'static int run_respawn(char **argv){mach_port_t bootstraport=88;\n'+branch+'\nreturn 99;\n}'])
    fixture=(Path(__file__).parent/'fixtures/jailbreakd_timing.c').read_text(encoding='utf-8')
    source=a.workdir.resolve()/'parent-timing.c'
    program=a.workdir.resolve()/('parent-timing.exe' if sys.platform=='win32' else 'parent-timing')
    source.write_text(('#define EXPECT_DEADLINE '+str(int(a.expect=='deadline'))+'\n')+fixture.replace('/* PRODUCTION */',production),encoding='utf-8')
    subprocess.run(cc+['-std=gnu11','-fblocks','-Wall','-Wextra','-Werror',
                      '-Wno-unused-function','-Wno-unused-variable',str(source),'-o',str(program)],check=True)
    for mode,name in enumerate(PARENT_MODES):
        r=subprocess.run([str(program),str(mode)],capture_output=True,text=True,timeout=10)
        assert r.returncode==0,(name,r.returncode,r.stdout,r.stderr)
        event=json.loads(r.stdout)
        cases.append(dict(name='jailbreakd-'+name,observation=event,stdout=r.stdout,stderr=r.stderr))
        print('jailbreakd-'+name+': '+r.stdout.strip(),flush=True)
    unsafe=sum(c['observation']['unsafe'] for c in cases)
    result=dict(provenance='independently rebuilt cross-component scheduler',
                revision=a.revision or 'working-tree',expectation=a.expect,inputs=inputs,
                acceptance_pass=unsafe==0,counterexamples=unsafe,cases=cases,
                limits='No real Mach IPC, kernel patch, SETEXEC or iOS scheduling; polling interleavings can vary. Final new-launchd DONE is simulated. NOT device acceptance.')
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return 1 if unsafe else 0


if __name__=='__main__':
    sys.exit(main())
