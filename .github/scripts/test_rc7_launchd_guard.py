#!/usr/bin/env python3
"""Host-side RC7 launchd regression; does not substitute for an iOS build.

Exercises the extracted bind compatibility hook with a stub, including a
full 16-bit ephemeral-port exhaustion case that previously looped forever.
Checks the spawn PID and blacklist error-path guards in the shipped source.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
launchd = (ROOT / 'BaseBin/launchdhook/src/roothider.m').read_text()
spawn = (ROOT / 'BaseBin/launchdhook/src/spawn_hook.c').read_text()

assert 'if (!blacklistedPidp)' in launchd
assert 'return ENOMEM;' in launchd
assert 'pid_t pid = (ret == 0) ? *blacklistedPidp : 0;' in launchd
assert 'if (ret == 0 && pidp) *pidp = pid;' in launchd
assert 'if (ret != 0) *blacklistedPidp = 0;' in launchd
assert 'JBLogDebug("__posix_spawn ret=%d pid=%d", r, (r == 0) ? *pid : 0);' in spawn
assert 'if (path && !strcmp(path, "/usr/libexec/xpcproxy"))' in spawn

start = launchd.index('int new_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)')
end = launchd.index('\nextern xpc_object_t (*orig_xpc_dictionary_create_reply)', start)
function = launchd[start:end]

prefix = r'''
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#undef IPPORT_HIFIRSTAUTO
#undef IPPORT_HILASTAUTO
#define IPPORT_HIFIRSTAUTO 49152
#define IPPORT_HILASTAUTO 65535
static int tries, fail_until, mode, first_port, last_port;
static int fake_bind(int sockfd, const struct sockaddr *addr, socklen_t size) {
    (void)sockfd; (void)size;
    if (!addr) { errno=EFAULT; return -1; }
    ++tries;
    if (addr->sa_family==AF_INET) last_port = ntohs(((const struct sockaddr_in *)addr)->sin_port);
    else if (addr->sa_family==AF_INET6) last_port = ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    if (tries==1) first_port=last_port;
    if (mode==1 || tries<=fail_until) { errno=EADDRINUSE; return -1; }
    if (mode==2) { errno=EINVAL; return -1; }
    return 0;
}
static int (*orig_bind)(int, const struct sockaddr *, socklen_t) = fake_bind;
static void reset(int how, int until) {
    tries=0; mode=how; fail_until=until; first_port=0; last_port=0;
}
'''
suffix = r'''
int main(void) {
    struct sockaddr_in a4={0}; a4.sin_family=AF_INET;
    struct sockaddr_in6 a6={0}; a6.sin6_family=AF_INET6;
    reset(0,2);
    assert(new_bind(1,(const struct sockaddr *)&a4,sizeof(a4))==0);
    assert(tries==3 && first_port==49152 && last_port==49154);
    reset(0,0);
    a4.sin_port=htons(1234);
    assert(new_bind(1,(const struct sockaddr *)&a4,sizeof(a4))==0);
    assert(tries==1 && last_port==1234);
    a4.sin_port=0;
    reset(1,0);
    assert(new_bind(1,(const struct sockaddr *)&a4,sizeof(a4))==-1);
    assert(errno==EADDRINUSE && tries==16384 && last_port==65535);
    reset(0,3);
    assert(new_bind(1,(const struct sockaddr *)&a6,sizeof(a6))==0);
    assert(tries==4 && last_port==49155);
    reset(1,0);
    assert(new_bind(1,(const struct sockaddr *)&a6,sizeof(a6))==-1);
    assert(errno==EADDRINUSE && tries==16384 && last_port==65535);
    reset(2,0);
    assert(new_bind(1,(const struct sockaddr *)&a6,sizeof(a6))==-1);
    assert(errno==EINVAL && tries==1);
    reset(0,0);
    assert(new_bind(1,NULL,sizeof(a4))==-1);
    assert(errno==EFAULT && tries==0);
    reset(0,0);
    assert(new_bind(1,(const struct sockaddr *)&a4,1)==0);
    assert(tries==1);
    puts("PASS: IPv4/IPv6 bind hook bounded at port 65535, error/NULL/nonzero-port paths");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='rc7-guard-') as temp:
    source = Path(temp) / 'guard.c'
    output = Path(temp) / 'guard'
    source.write_text(prefix + function + suffix)
    subprocess.run(shlex.split(os.environ.get('CC','cc')) + ['-std=c11','-Wall','-Wextra','-Werror','-O2', str(source),'-o',str(output)], check=True)
    subprocess.run([str(output)], check=True)
print('PASS: spawn failure PID, blacklist OOM and early-boot NULL-path source checks')
