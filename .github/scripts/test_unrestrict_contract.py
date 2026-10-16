#!/usr/bin/env python3
"""Independent reconstruction of F3's acceptance contract, not the audit fixture.

Executes the extracted production function with virtual monotonic time and inert
process/signal substitutes. No real signal, kernel operation, or device reboot.
Default mode is an acceptance gate: old or deliberately broken code must fail.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def extract(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for pos in range(opening, len(source)):
        depth += (source[pos] == '{') - (source[pos] == '}')
        if depth == 0:
            return source[start:pos + 1]
    raise ValueError(signature)


PREFIX = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#ifndef SIGCONT
#define SIGCONT 19
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 6
#endif
static int mode, queries, callbacks, resumes, clock_calls;
static int64_t milliseconds;
static int fail(const char *message) { fprintf(stderr,"CONTRACT_FAILURE: %s\n",message); return 1; }
static int __attribute__((unused)) test_clock_gettime(int clock, struct timespec *ts) {
    if (clock != CLOCK_MONOTONIC) { fputs("wrong clock\n",stderr); exit(4); }
    clock_calls++;
    if ((mode==6 && clock_calls==1) || (mode==7 && clock_calls==3)) { errno=EIO;return -1; }
    ts->tv_sec=milliseconds/1000;ts->tv_nsec=(milliseconds%1000)*1000000;return 0;
}
static int test_usleep(unsigned usecs) {
    if(mode==11 && usecs==100000){errno=EINTR;return -1;}
    milliseconds+=usecs/1000;
    if(mode==8 && usecs==100000) milliseconds+=11000;
    return 0;
}
static int proc_paused(pid_t pid,bool *paused) {
    if(pid!=42){fputs("wrong target\n",stderr);exit(4);}
    queries++;
    /* Harness escape only. Old unbounded code must fail, never appear to pass. */
    if(queries>20000){fputs("HARNESS_GUARD: production wait did not terminate\n",stderr);exit(3);}
    if(mode==2)return -1;
    if(mode==12 && queries==2)return -1;
    if(mode==13 && queries==2)milliseconds+=11000;
    *paused=mode!=1 && !(mode==9 && queries>1);
    return 0;
}
static int test_callback(pid_t pid) {
    if(pid!=42){fputs("wrong callback target\n",stderr);exit(4);}
    callbacks++;
    if(milliseconds<100){fputs("callback before preparation delay\n",stderr);exit(4);}
    if(mode==3)return 47;
    /* Callback is synchronous: a late return is not concurrent cancellation. */
    if(mode==10)milliseconds+=20000;
    return 0;
}
static int test_kill(pid_t pid,int sig) {
    if(pid!=42 || sig!=SIGCONT || callbacks!=1){fputs("invalid resume\n",stderr);exit(4);}
    resumes++;
    if(mode==4){errno=EPERM;return -1;}
    return 0;
}
#define clock_gettime test_clock_gettime
#define usleep test_usleep
#define kill test_kill
#define proc_get_path(pid,buf) "/fixture/target"
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
'''

CASES = r'''
int main(int argc,char **argv) {
    if(argc!=2)return 4;
    mode=atoi(argv[1]);
    int result=unrestrict(42,test_callback,mode!=5);
    if(mode==1 || mode==8 || mode==9 || mode==13) {
        if(result!=ETIMEDOUT || callbacks || resumes)return fail("timeout must not patch or resume");
        if(mode==1 && milliseconds>10100)return fail("wait exceeded monotonic deadline");
    } else if(mode==2 || mode==12) {
        if(result!=-1 || callbacks || resumes)return fail("query failure must stop before callback");
    } else if(mode==3) {
        if(result!=47 || callbacks!=1 || resumes)return fail("callback error must be preserved without resume");
    } else if(mode==4) {
        if(result!=EPERM || callbacks!=1 || resumes!=1)return fail("resume errno must propagate");
    } else if(mode==6 || mode==7) {
        if(result!=EIO || callbacks || resumes)return fail("clock failure must fail closed");
    } else if(mode==11) {
        if(result!=EINTR || callbacks || resumes)return fail("interrupted preparation must not patch");
    } else {
        if(result || callbacks!=1 || resumes!=(mode==5?0:1))return fail("normal ownership/ordering");
    }
    printf("case=%d result=%d queries=%d callbacks=%d resumes=%d virtual_ms=%lld\n",
           mode,result,queries,callbacks,resumes,(long long)milliseconds);
    return 0;
}
'''

MODES = {0: 'normal', 1: 'never-pauses', 2: 'query-failure', 3: 'callback-failure',
         4: 'resume-failure', 5: 'caller-retains-suspended-child', 6: 'initial-clock-failure',
         7: 'preparation-clock-failure', 8: 'late-preparation', 9: 'pause-lost-during-preparation',
         10: 'late-synchronous-callback', 11: 'interrupted-preparation',
         12: 'recheck-query-failure', 13: 'late-query-result'}

# Separate correction contract. The original bounded-wait assertions above
# remain the default and still FAIL: an unbounded wait is not F3 closure.
CORRECTION_CASES = r'''
int main(int argc,char **argv) {
    if(argc!=2)return 4;
    mode=atoi(argv[1]);
    int result=unrestrict(42,test_callback,mode!=5);
    if(mode==2 || mode==12) {
        if(result!=-1 || callbacks || resumes)return fail("query error/ownership");
    } else if(mode==3) {
        if(result!=47 || callbacks!=1 || resumes)return fail("callback error/ownership");
    } else if(mode==4) {
        if(result!=EPERM || callbacks!=1 || resumes!=1)return fail("resume error propagation");
    } else if(mode==11) {
        if(result!=EINTR || callbacks || resumes)return fail("preparation failure");
    } else {
        if(result || callbacks!=1 || resumes!=(mode==5?0:1))return fail("late preparation must complete");
    }
    if(clock_calls)return fail("unsupported preparation timer remains");
    printf("case=%d result=%d callbacks=%d resumes=%d virtual_ms=%lld\n",
        mode,result,callbacks,resumes,(long long)milliseconds);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--source', type=Path, default=ROOT / 'BaseBin/libjailbreak/src/roothider/common.m')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--workdir', type=Path)
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--darwin-headers', action='store_true')
    parser.add_argument('--regression-correction', action='store_true',
                        help='Only validate deadline regression correction; does not certify F3')
    args = parser.parse_args()
    function = extract(args.source.read_text(encoding='utf-8'), 'int unrestrict(')
    cc = [str(args.zig.resolve()), 'cc'] if args.zig else ['cc']
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror']
    if sys.platform == 'darwin':
        flags += ['-fsanitize=address,undefined']
    results = {'provenance': 'independently rebuilt', 'source': str(args.source), 'cases': [], 'mutations': []}
    cases_source = CORRECTION_CASES if args.regression_correction else CASES
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='unrestrict-contract-')
    with context as directory:
        folder = Path(directory)
        source = folder / 'contract.c'
        program = folder / ('contract.exe' if sys.platform == 'win32' else 'contract')

        def compile_fn(body, extra=None):
            source.write_text(PREFIX + body + cases_source, encoding='utf-8')
            subprocess.run(cc + flags + (extra or []) + [str(source), '-o', str(program)], check=True)

        compile_fn(function)
        for mode, name in MODES.items():
            if args.regression_correction and mode in (1, 9):
                continue  # separately observed below, never labelled as safe
            result = subprocess.run([str(program), str(mode)], capture_output=True, text=True, timeout=5)
            results['cases'].append(dict(name=name, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
            print(f'{name}: {"PASS" if result.returncode == 0 else "FAIL"} {result.stdout.strip()} {result.stderr.strip()}', flush=True)
        all_pass = all(case['exit_code'] == 0 for case in results['cases'])
        if args.mutations and all_pass:
            mutations = [
                ('remove-deadline', 'return ETIMEDOUT;', '{ /* broken deadline */ }', 1),
                ('ignore-resume-error', 'return errno ? errno : EIO;', 'return 0;', 4),
                ('ignore-query-error', 'return -1;', 'return 0;', 2),
                ('ignore-callback-error', 'return ret;', 'return 0;', 3),
                ('skip-preparation', 'usleep(100*1000)', 'usleep(0)', 0),
            ]
            if args.regression_correction:
                mutations = [entry for entry in mutations if entry[0] != 'remove-deadline']
                mutations.append(('skip-pause-recheck', 'if (proc_paused(pid, &paused) != 0) return -1;', '', 12))
            for name, old, new, mode in mutations:
                if old not in function:
                    raise AssertionError('mutation target missing: ' + name)
                broken = function.replace(old, new)
                compile_fn(broken)
                result = subprocess.run([str(program), str(mode)], capture_output=True, text=True, timeout=5)
                rejected = result.returncode != 0
                results['mutations'].append(dict(name=name, rejected=rejected, exit_code=result.returncode,
                                                 stdout=result.stdout, stderr=result.stderr))
                print(f'mutation {name}: {"REJECTED" if rejected else "ESCAPED"}', flush=True)
                all_pass = all_pass and rejected
        if args.darwin_headers and all_pass:
            source.write_text(PREFIX + function + cases_source, encoding='utf-8')
            for target in ['aarch64-macos', 'x86_64-macos']:
                subprocess.run(cc + flags + ['-target', target, '-c', str(source), '-o', str(folder / (target + '.o'))], check=True)
            results['darwin_headers'] = 'compiled; not an Apple component build'
        results['acceptance_pass'] = all_pass
        if args.regression_correction:
            compile_fn(function)
            results['known_unbounded'] = []
            for mode in (1,9):
                r = subprocess.run([str(program),str(mode)],capture_output=True,text=True,timeout=5)
                observed = r.returncode == 3 and 'HARNESS_GUARD' in r.stderr
                results['known_unbounded'].append(dict(name=MODES[mode],observed=observed,
                    exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
                all_pass = all_pass and observed
            results['correction_pass'] = all_pass
            results['acceptance_pass'] = False
            results['limits'] = 'F3 remains FAIL: baseline unbounded preparation and post-DONE failure ownership remain unresolved.'
        if args.output:
            args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
        return 0 if all_pass else 1


if __name__ == '__main__':
    sys.exit(main())
