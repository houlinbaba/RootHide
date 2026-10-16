/* Virtual time; production RESPAWN_REQUIRED branch and its cleanup below.
 * No process, Mach, kernel, dispatch or signal operation reaches the OS. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
typedef int pid_t;
typedef void *posix_spawnattr_t;
typedef unsigned mach_port_t;
typedef long long dispatch_time_t;
#define SIGCONT 19
#define SIGKILL 9
#define WNOHANG 1
#define POSIX_SPAWN_START_SUSPENDED 128
#define MACH_PORT_NULL 0
#define DISPATCH_TIME_NOW 0
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
#define proc_get_path(p,b) "/fixture/jailbreakd"
static int scenario, now_ms, pause_at, callback_delay, callbacks, resumes, kills, reaps, deferred;
static bool child_alive, child_paused, attributes_live, registered_port;
static void (^pending)(void);
static int pending_at, cleanup_at;
// This production callback captures scalar PID/retry values only. Copy that
// Clang Block's storage, refusing object/byref capture helpers. This is an
// inert queue model, not validation of Apple libdispatch/Blocks lifetimes.
struct block_descriptor { unsigned long reserved, size; };
struct block_layout { void *isa; int flags, reserved; void *invoke; struct block_descriptor *descriptor; };
static char *env[]={NULL};
#undef environ
#define environ env
static int test_unsetenv(const char *s){assert(!strcmp(s,"RESPAWN_REQUIRED"));return 0;}
#define unsetenv test_unsetenv
static int _NSGetExecutablePath(char *s,uint32_t *n){assert(*n>=32);strcpy(s,"/fixture/jailbreakd");return 0;}
static int posix_spawnattr_init(posix_spawnattr_t *a){*a=(void*)1;attributes_live=true;return 0;}
static int posix_spawnattr_setflags(posix_spawnattr_t *a,int f){assert(*a && f==128);return 0;}
static int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *a,mach_port_t *p,unsigned n){assert(*a && n==3 && p[2]==88);registered_port=true;return 0;}
static int posix_spawnattr_destroy(posix_spawnattr_t *a){assert(*a);attributes_live=false;return 0;}
static int posix_spawn(pid_t *p,const char *s,const void *f,const posix_spawnattr_t *a,char *const av[],char *const ev[]){
    (void)s;(void)f;(void)av;(void)ev;assert(*a && registered_port);*p=520;child_alive=true;return 0;
}
static int __attribute__((unused)) test_clock_gettime(int c,struct timespec *ts){(void)c;ts->tv_sec=now_ms/1000;ts->tv_nsec=now_ms%1000*1000000;return 0;}
#define clock_gettime test_clock_gettime
static int usleep(unsigned u){now_ms+=u/1000;return 0;}
static int proc_paused(pid_t p,bool *paused){assert(p==520);if(scenario==4)return -1;*paused=now_ms>=pause_at;child_paused=*paused;return 0;}
static int proc_patch_dyld(pid_t p){assert(p==520 && child_alive && child_paused);callbacks++;now_ms+=callback_delay;return (scenario==5 || scenario==8 || scenario==9)?EIO:0;}
static bool dyld_patch_enabled(void){return true;}
static int kill(pid_t p,int sig){
    assert(p==520);
    if(sig==SIGCONT){resumes++;if(scenario==6){errno=EPERM;return -1;}child_paused=false;return 0;}
    assert(sig==SIGKILL);kills++;if(scenario==9){errno=EPERM;return -1;}
    if(scenario!=8)child_alive=false;else cleanup_at=now_ms;return 0;
}
static pid_t waitpid(pid_t p,int *s,int f){assert(p==520 && s && f==WNOHANG);reaps++;return child_alive?0:p;}
static dispatch_time_t dispatch_time(dispatch_time_t t,long long d){assert(t==0);return now_ms+d/1000000;}
static void *dispatch_get_global_queue(int p,int f){assert(!p&&!f);return NULL;}
static void dispatch_after(dispatch_time_t t,void *q,void (^block)(void)){
    assert(!q && !pending);struct block_layout *layout=(void*)block;
    assert(!(layout->flags&(1<<25)) && layout->descriptor->size<1024);
    void *copy=malloc(layout->descriptor->size);assert(copy);memcpy(copy,layout,layout->descriptor->size);
    deferred++;pending=copy;pending_at=(int)t;
}
#ifdef _WIN32
void *_NSConcreteStackBlock[32], *_NSConcreteGlobalBlock[32];
void _Block_object_assign(void *o,const void *v,int f){(void)f;*(const void**)o=v;}
void _Block_object_dispose(const void *v,int f){(void)v;(void)f;}
#endif
/* PRODUCTION */
int main(int argc,char **argv){
    assert(argc==2);scenario=atoi(argv[1]);
    if(scenario==1)pause_at=9800;
    if(scenario==2)pause_at=9950;
    if(scenario==3)pause_at=11000;
    if(scenario==7)callback_delay=20000;
    if(scenario==8 || scenario==9)pause_at=11000;
    int result=run_respawn(argv);
    bool alive_at_return=child_alive;
    while(pending){
        void (^block)(void)=pending;pending=NULL;now_ms=pending_at;
        if(scenario==8 && now_ms-cleanup_at>=150)child_alive=false;
        block();free((void*)block);
    }
    assert(!attributes_live);
    if(scenario==0 || scenario==1 || scenario==7 || (!EXPECT_DEADLINE && (scenario==2 || scenario==3))){assert(result==0 && callbacks==1 && resumes==1 && !kills);}
    if((EXPECT_DEADLINE && (scenario==2 || scenario==3)) || scenario==4 || scenario==5){assert(result==5 && kills==1 && !resumes && !child_alive);}
    if(scenario==6){assert(result==7 && resumes==1 && kills==1 && !child_alive);}
    if((EXPECT_DEADLINE && (scenario==2 || scenario==3)) || scenario==4)assert(!callbacks);
    if(scenario==8)assert(result==5 && kills==1 && alive_at_return && !child_alive && deferred==3 && reaps==4);
    if(scenario==9)assert(result==5 && kills==1 && child_alive && deferred==21 && reaps==22);
    bool unsafe=child_alive && result!=0;
    printf("{\"scenario\":%d,\"elapsed_ms\":%d,\"result\":%d,\"callbacks\":%d,\"resumes\":%d,\"kills\":%d,\"reaps\":%d,\"deferred_reap\":%d,\"alive_at_return\":%s,\"child_alive\":%s,\"unsafe\":%s}\n",
        scenario,now_ms,result,callbacks,resumes,kills,reaps,deferred,alive_at_return?"true":"false",child_alive?"true":"false",unsafe?"true":"false");
    return 0;
}
