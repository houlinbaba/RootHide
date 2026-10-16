#!/usr/bin/env python3
"""Execute the production dyld metadata updater and respawn failure cleanup.

Mach and kernel I/O are substitutes. This verifies error/retry contracts and
parent control flow, not device layout, kernel writes, or a userspace reboot.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

from test_dyld_entry_redirect import extract

ROOT = Path(__file__).resolve().parents[2]

PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#define DYLD_INFO_MAX_SEARCH_INDEX 200
#define KERN_SUCCESS 0
#define TASK_DYLD_INFO 17
#define TASK_DYLD_INFO_COUNT 5
#define SIGKILL 9
#define SIGCONT 19
#ifndef WNOHANG
#define WNOHANG 1
#endif
typedef void *task_info_t;
typedef int kern_return_t;
typedef struct { uint64_t all_image_info_addr, all_image_info_size; } task_dyld_info_data_t;
static uint64_t self_words[210], target_words[210];
static int fail_info, short_info, empty_info, fail_self, fail_proc=1, fail_launchd_task;
static int fail_read, read_calls, fail_write, write_calls;
static int info_calls;
static int fail_resume, resumes, kills, reaps, deferred_reaps, checkins, callbacks;
static bool enabled=true;
static const char *last_phase;
static pthread_mutex_t log_lock=PTHREAD_MUTEX_INITIALIZER;
static void log_message(const char *s, ...) { (void)s; }
#define JBLogDebug log_message
#define JBLogError log_message
#define proc_get_path(p,b) "/test/jailbreakd"
static void roothide_stage_log(const char *fmt,...) {
    pthread_mutex_lock(&log_lock);
    va_list args;va_start(args,fmt);
    if(strstr(fmt,"phase=%s"))last_phase=va_arg(args,const char*);
    va_end(args);
    pthread_mutex_unlock(&log_lock);
}
#define roothide_reboot_log log_message
static unsigned mach_task_self(void) { return 1; }
static uint64_t task_self(void) { return fail_self?0:0x10000; }
static uint64_t proc_find(int p) { assert(p==1);return fail_proc?0:0x30000; }
static uint64_t proc_task(uint64_t p) { assert(p==0x30000);return fail_launchd_task?0:0x20000; }
static int task_info(unsigned p,int f,task_info_t out,uint32_t *n) {
    assert(p==1 && f==17 && *n==5);
    info_calls++;
    if(fail_info)return 5;
    if(short_info)*n=1;
    *(task_dyld_info_data_t*)out=(task_dyld_info_data_t){empty_info?0:0x12345678,0x800};return 0;
}
static int kreadbuf(uint64_t a,void *out,size_t n) {
    assert((a>=0x10000 && a+n<=0x10000+sizeof(self_words)) ||
           (a>=0x20000 && a+n<=0x20000+sizeof(target_words)));
    read_calls++;
    if(read_calls==fail_read)return -5;
    memcpy(out, a<0x20000?(char*)self_words+(a-0x10000):(char*)target_words+(a-0x20000),n);return 0;
}
static int kwritebuf(uint64_t a,const void *in,size_t n) {
    assert(a>=0x20000 && a+n<=0x20000+sizeof(target_words));write_calls++;
    if(write_calls==fail_write)return -7;
    memcpy((char*)target_words+(a-0x20000),in,n);return 0;
}
static int kwrite64(uint64_t a,uint64_t v) { return kwritebuf(a,&v,sizeof(v)); }
'''

PARENT_PREFIX = r'''
static int mock_unrestrict_clock(int clock,struct timespec *ts) {
    assert(clock==CLOCK_MONOTONIC);ts->tv_sec=0;ts->tv_nsec=0;return 0;
}
#define clock_gettime mock_unrestrict_clock
static int proc_paused(pid_t pid,bool *paused) { assert(pid==520);*paused=true;return 0; }
static int usleep(unsigned usecs) { assert(usecs==100000);return 0; }
static int kill(pid_t pid,int sig) {
    assert(pid==520);
    if(sig==SIGKILL){kills++;return 0;}
    assert(sig==SIGCONT);resumes++;if(fail_resume){errno=ESRCH;return -1;}return 0;
}
static pid_t mock_waitpid(pid_t pid,int *status,int options) {
    assert(pid==520 && status && options==WNOHANG);reaps++;return pid;
}
/* Darwin headers may already declare waitpid. Replace only the calls in the
 * production cleanup below, without redeclaring the system function. */
#define waitpid mock_waitpid
static void scheduleRespawnedJailbreakdChildReap(pid_t pid,unsigned int n) {
    assert(pid==520 && n==20);deferred_reaps++;
}
static bool dyld_patch_enabled(void) { return enabled; }
static int proc_patch_dyld(pid_t pid) {
    assert(pid==520);callbacks++;return task_set_dyld_info(0x20000,0x98760000,0x900);
}
'''

CASES = r'''
static void initialize(void) {
    self_words[20]=0x12345678;self_words[21]=0x800;
    target_words[60]=1;target_words[64]=1;
}
static void *concurrent_update(void *arg) {
    (void)arg;
    assert(!task_set_dyld_info(0x20000,0x98760000,0x900));return NULL;
}
int main(int argc,char **argv) {
    assert(argc==2);const char *mode=argv[1];initialize();
    if(!strcmp(mode,"concurrent")) {
        pthread_t threads[8];
        for(int i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,concurrent_update,NULL));
        for(int i=0;i<8;i++)assert(!pthread_join(threads[i],NULL));
        assert(info_calls==1 && write_calls==24);
    } else if(!strcmp(mode,"info-retry")) {
        fail_info=1;assert(task_set_dyld_info(0x20000,1,1)==5 && !write_calls);
        fail_info=0;assert(!task_set_dyld_info(0x20000,0x98760000,0x900));
    } else if(!strcmp(mode,"address-read-retry") || !strcmp(mode,"metadata-read-retry")) {
        fail_read=!strcmp(mode,"address-read-retry")?3:24;
        assert(task_set_dyld_info(0x20000,1,1)==-5 && !write_calls);
        fail_read=0;assert(!task_set_dyld_info(0x20000,0x98760000,0x900));
    } else if(!strcmp(mode,"missing-pattern-retry")) {
        target_words[60]=0;assert(task_set_dyld_info(0x20000,1,1)==-1 && !write_calls && !strcmp(last_phase,"metadata_offset_missing"));
        target_words[60]=1;assert(!task_set_dyld_info(0x20000,0x98760000,0x900));
    } else if(!strcmp(mode,"launchd-then-child")) {
        target_words[60]=0;fail_proc=0;
        assert(!task_set_dyld_info(0x20000,0x98760000,0x900));
        assert(write_calls==2);
        target_words[60]=1;assert(!task_set_dyld_info(0x20000,0x98760000,0x900));
        assert(write_calls==5 && target_words[60]==0);
    } else if(!strcmp(mode,"invalid-arguments")) {
        assert(task_set_dyld_info(0,1,1)==-1 && !read_calls && !write_calls);
        assert(task_set_dyld_info(0x20000,0,1)==-1 && !read_calls && !write_calls);
        assert(task_set_dyld_info(0x20000,1,0)==-1 && !read_calls && !write_calls);
        return 0;
    } else if(!strcmp(mode,"bad-self")) {
        fail_self=1;assert(task_set_dyld_info(0x20000,1,1)==-1 && !read_calls && !write_calls);return 0;
    } else if(!strcmp(mode,"short-info") || !strcmp(mode,"empty-info")) {
        short_info=!strcmp(mode,"short-info");empty_info=!strcmp(mode,"empty-info");
        assert(task_set_dyld_info(0x20000,1,1)==-1 && !read_calls && !write_calls);return 0;
    } else if(!strcmp(mode,"missing-address")) {
        self_words[20]=0;assert(task_set_dyld_info(0x20000,1,1)==-1 && !write_calls && !strcmp(last_phase,"address_offsets_missing"));return 0;
    } else if(!strcmp(mode,"missing-launchd-task")) {
        target_words[60]=0;fail_proc=0;fail_launchd_task=1;
        assert(task_set_dyld_info(0x20000,1,1)==-1 && !write_calls);return 0;
    } else if(!strncmp(mode,"write-",6)) {
        fail_write=atoi(mode+6);assert(fail_write>=1 && fail_write<=3);
        assert(task_set_dyld_info(0x20000,1,1)==-7 && write_calls==fail_write);
        const char *phases[]={"metadata_clear","address_write","size_write"};
        assert(!strcmp(last_phase,phases[fail_write-1]));return 0;
    } else if(!strncmp(mode,"parent-",7)) {
        const char *failure=mode+7;
        if(!strcmp(failure,"read"))fail_read=1;
        else if(!strcmp(failure,"write"))fail_write=2;
        else if(!strcmp(failure,"missing")){target_words[60]=0;fail_proc=1;}
        else if(!strcmp(failure,"resume"))fail_resume=1;
        else assert(!strcmp(failure,"success"));
        int r=run_parent_patch(520);
        assert(callbacks==1 && !deferred_reaps);
        if(!strcmp(failure,"success")){assert(r==0 && resumes==1 && !kills && !reaps && !checkins);}
        else {assert(r==(!strcmp(failure,"resume")?7:5) && kills==1 && reaps==1 && !checkins);
              assert(resumes==(!strcmp(failure,"resume")?1:0));}
        return 0;
    } else {
        assert(!strcmp(mode,"normal"));assert(!task_set_dyld_info(0x20000,0x98760000,0x900));
    }
    assert(target_words[20]==0x98760000 && target_words[21]==0x900 && target_words[60]==0);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    folder = ROOT / 'BaseBin/libjailbreak/src/roothider'
    source = (folder / 'dyld_patch.m').read_text(encoding='utf-8')
    updater = extract(source, 'int task_set_dyld_info(')
    assert 'abort(' not in updater and 'dispatch_once(' not in updater
    unrestrict = extract((folder / 'common.m').read_text(encoding='utf-8'), 'int unrestrict(')
    main_source = (ROOT / 'BaseBin/jailbreakd/src/main.m').read_text(encoding='utf-8')
    cleanup = extract(main_source, 'static void terminateRespawnedJailbreakdChild(')
    start = main_source.index('int unrestrictResult = unrestrict(pid, proc_patch_dyld, false);')
    end = main_source.index('\n\t\t}\n', start)
    parent = 'static int run_parent_patch(pid_t pid) {\n' + main_source[start:end] + '\ncheckins++;return 0;\n}\n'
    harness_source = PREFIX + updater + PARENT_PREFIX + unrestrict + cleanup + parent + CASES
    modes = ['normal', 'concurrent', 'info-retry', 'address-read-retry', 'metadata-read-retry',
             'missing-pattern-retry', 'launchd-then-child', 'invalid-arguments',
             'bad-self', 'short-info', 'empty-info', 'missing-address', 'missing-launchd-task',
             'write-1', 'write-2', 'write-3', 'parent-read', 'parent-write',
             'parent-missing', 'parent-resume', 'parent-success']
    context = nullcontext(args.workdir.resolve()) if args.workdir else tempfile.TemporaryDirectory(prefix='dyld-metadata-')
    compiler = [str(args.zig.resolve()), 'cc'] if args.zig else ['cc']
    with context as directory:
        temp = Path(directory)
        harness = temp / 'dyld_metadata.c'
        binary = temp / ('dyld_metadata.exe' if sys.platform == 'win32' else 'dyld_metadata')
        sanitizers = ['-fsanitize=address,undefined'] if sys.platform == 'darwin' else []
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread']
        harness.write_text(harness_source, encoding='utf-8')
        subprocess.run(compiler + sanitizers + flags + [str(harness), '-o', str(binary)], check=True)
        for mode in modes:
            subprocess.run([str(binary), mode], check=True, timeout=10)
        print(f'PASS: {len(modes)} production metadata/parent cases; retries, exact write errors, child cleanup, no resume on patch failure')
        if args.zig and sys.platform != 'darwin':
            # Zig supplies Darwin headers: catch SDK declarations/macros even
            # when the host model is executed on Windows or Linux.
            for target in ['aarch64-macos', 'x86_64-macos']:
                object_file = temp / f'dyld_metadata-{target}.o'
                subprocess.run(compiler + ['-target', target] + flags +
                               ['-c', str(harness), '-o', str(object_file)], check=True)
            print('PASS: metadata harness compiles against Darwin headers for both Mac targets')
        broken = updater.replace('return result;', 'return 0;')
        assert broken != updater
        harness.write_text(harness_source.replace(updater, broken), encoding='utf-8')
        subprocess.run(compiler + sanitizers + flags + [str(harness), '-o', str(binary)], check=True)
        negative = subprocess.run([str(binary), 'write-2'], capture_output=True, timeout=10)
        assert negative.returncode != 0, 'false metadata success escaped the regression'
        print('PASS: false metadata success is rejected; device reboot remains unverified')


if __name__ == '__main__':
    main()
