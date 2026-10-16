/* Virtual-time cross-component host scheduler. No real Mach, signals or exec.
 * Production sender, hook prefix, helper main and unrestrict are inserted below.
 * pthreads execute both real control flows; virtual time advances only when
 * both flows are parked. Thread interleavings may vary by a polling interval.
 * Blocks are used only while their producer is live.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#ifdef _WIN32
typedef int test_pid_t;
#define pid_t test_pid_t
#endif
#ifndef SIGCONT
#define SIGCONT 19
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef WNOHANG
#define WNOHANG 1
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 6
#endif
typedef unsigned mach_port_t, task_t, mach_msg_type_number_t;
typedef int kern_return_t;
typedef void *posix_spawnattr_t, *xpc_object_t;
typedef uint64_t dispatch_time_t;
typedef void (^dispatch_block_t)(void);
struct object {int kind, refs, owner, signals, canceled, busy; dispatch_block_t event,cancel; struct object *queue;};
typedef struct object *dispatch_source_t, *dispatch_queue_t, *dispatch_semaphore_t;
#define DISPATCH_QUEUE_SERIAL NULL
#define DISPATCH_SOURCE_TYPE_MACH_RECV 1
#define DISPATCH_TIME_NOW 0
#define NSEC_PER_MSEC 1000000LL
#define NSEC_PER_SEC 1000000000LL
#define MACH_PORT_NULL 0
#define MACH_PORT_VALID(p) ((p) && (p)!=(unsigned)-1)
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_MSG_TYPE_MAKE_SEND 20
#define KERN_SUCCESS 0
#define JBS_BOOMERANG_DONE 42
#define JBROOT_PATH(p) p
#define MNT_FORCE 1
#define LOG_PROCESS_LAUNCHES 0
#define __builtin_available(...) 1
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
#define proc_get_path(p,b) "/fixture/target"
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static _Thread_local int role;
static pthread_t helper_thread;
static bool helper_started, finished[2], parked[2], helper_dead, helper_killed;
static int64_t wake_at[2], now_ms, done_at=-1, prepare_at=-1, patch_at=-1, exit_at=-1;
static int scenario, update_delay, start_delay, callback_delay;
static bool done_sent, target_paused, target_resumed, helper_serving, setexec_seen, setexec_dead;
static bool old_port, helper_port, registered_helper, helper_message, reply_sent;
static int old_result, helper_result, patches, resumes, child_reaped, helper_waits;
static int gBoomerangServer;
static bool gInEarlyBoot;
static char *test_environment[]={NULL};
#undef environ
#define environ test_environment
static char saved_pid[32];
static struct object objects[24], main_queue, *sources[2];
static int object_count;
#ifdef _WIN32
void *_NSConcreteStackBlock[32], *_NSConcreteGlobalBlock[32];
void _Block_object_assign(void *out,const void *v,int flags){(void)flags;*(const void **)out=v;}
void _Block_object_dispose(const void *v,int flags){(void)v;(void)flags;}
#endif
static void notify(void){pthread_cond_broadcast(&changed);}
static void park_locked(int64_t until){
    parked[role]=true;wake_at[role]=until;notify();
    pthread_cond_wait(&changed,&lock);
    parked[role]=false;notify();
}
static void helper_cleanup_locked(int result){
    helper_result=result;helper_dead=true;finished[1]=true;parked[1]=false;
    helper_port=false;helper_serving=false;exit_at=now_ms;notify();
}
static void exit_helper(int result){
    pthread_mutex_lock(&lock);helper_cleanup_locked(result);pthread_mutex_unlock(&lock);pthread_exit(NULL);
}
#define exit exit_helper
static struct object *object_new(int kind){
    struct object *o=&objects[object_count++];assert(object_count<24);memset(o,0,sizeof(*o));o->kind=kind;o->refs=1;o->owner=role;return o;
}
static void dispatch_retain(struct object *o){o->refs++;}
static void dispatch_release(struct object *o){assert(o && o->refs>0);if(!--o->refs && o->queue)o->queue->refs--;}
static dispatch_queue_t dispatch_queue_create(const char *label,void *a){(void)label;(void)a;return object_new(2);}
static dispatch_queue_t dispatch_get_main_queue(void){return &main_queue;}
static dispatch_semaphore_t dispatch_semaphore_create(long n){assert(!n);return object_new(1);}
static dispatch_source_t dispatch_source_create(int t,uintptr_t p,unsigned mask,dispatch_queue_t q){
    (void)t;(void)p;(void)mask;struct object *o=object_new(3);o->queue=q;dispatch_retain(q);sources[role]=o;return o;
}
static void dispatch_source_set_event_handler(struct object *o,dispatch_block_t b){o->event=b;}
static void dispatch_source_set_cancel_handler(struct object *o,dispatch_block_t b){o->cancel=b;}
static void dispatch_resume(struct object *o){(void)o;}
static void maybe_cancel(struct object *o){
    if(o && o->canceled && !o->busy && o->cancel){dispatch_block_t b=o->cancel;o->cancel=NULL;b();}
}
static void dispatch_source_cancel(struct object *o){
    pthread_mutex_lock(&lock);o->canceled=1;pthread_mutex_unlock(&lock);maybe_cancel(o);
}
static long dispatch_semaphore_signal(struct object *o){pthread_mutex_lock(&lock);o->signals++;notify();pthread_mutex_unlock(&lock);return 0;}
static dispatch_time_t dispatch_time(dispatch_time_t n,int64_t d){assert(!n);pthread_mutex_lock(&lock);int64_t t=now_ms+d/1000000;pthread_mutex_unlock(&lock);return t;}
static long dispatch_semaphore_wait(struct object *o,dispatch_time_t deadline){
    pthread_mutex_lock(&lock);
    while(!o->signals && now_ms<(int64_t)deadline)park_locked(deadline);
    long r=o->signals?0:1;if(o->signals)o->signals--;pthread_mutex_unlock(&lock);return r;
}
static void dispatch_main(void){
    pthread_mutex_lock(&lock);helper_serving=true;notify();
    while(!helper_message && !helper_killed)park_locked(INT64_MAX);
    if(helper_killed){helper_cleanup_locked(-99);pthread_mutex_unlock(&lock);pthread_exit(NULL);}
    pthread_mutex_unlock(&lock);sources[1]->event();assert(!"helper DONE handler must exit");
}
static int mach_task_self(void){return role+1;}
static int mach_port_allocate(int task,int right,mach_port_t *p){(void)task;(void)right;*p=role?202:101;if(role)helper_port=true;else old_port=true;return 0;}
static int mach_port_insert_right(int t,mach_port_t p,mach_port_t r,int f){(void)t;(void)p;(void)r;(void)f;return 0;}
static int mach_port_destroy(int t,mach_port_t p){(void)t;assert(p==101);old_port=false;return 0;}
static int mach_port_deallocate(int t,mach_port_t p){(void)t;(void)p;return 0;}
static int mach_ports_lookup(int t,mach_port_t **p,mach_msg_type_number_t *n){
    (void)t;static mach_port_t slots[2][3];slots[role][2]=role?101:(helper_dead?(unsigned)-1:202);*p=slots[role];*n=3;return 0;
}
static int mach_ports_register(int t,mach_port_t *ports,unsigned n){(void)t;assert(n==3);registered_helper=ports[2]!=0;return 0;}
static int task_for_pid(int self,int pid,task_t *out){(void)self;assert(pid==1);*out=77;return 0;}
static void jbclient_xpc_set_custom_port(mach_port_t p){(void)p;}
static void crashreporter_start(void){}
static int test_setsid(void){return 0;}
#define setsid test_setsid
static int jbclient_initialize_primitives_internal(bool pte){
    (void)pte;
    if(role==1 && scenario==3)return 5;
    if(role==1 && scenario==4){pthread_mutex_lock(&lock);while(!helper_killed)park_locked(INT64_MAX);helper_cleanup_locked(-99);pthread_mutex_unlock(&lock);pthread_exit(NULL);}
    return 0;
}
static int xpc_pipe_receive(mach_port_t p,xpc_object_t *o){*o=(void *)(uintptr_t)p;return 0;}
static int jbserver_received_boomerang_xpc_message(int *s,xpc_object_t o){
    (void)s;if((uintptr_t)o==202){pthread_mutex_lock(&lock);reply_sent=true;notify();pthread_mutex_unlock(&lock);}return JBS_BOOMERANG_DONE;
}
static void xpc_release(xpc_object_t o){(void)o;}
static int jbclient_boomerang_done(void){
    if(role==1){
        pthread_mutex_lock(&lock);done_at=now_ms;done_sent=true;sources[0]->busy=1;pthread_mutex_unlock(&lock);
        sources[0]->event();
        pthread_mutex_lock(&lock);sources[0]->busy=0;pthread_mutex_unlock(&lock);maybe_cancel(sources[0]);
        pthread_mutex_lock(&lock);while(now_ms<start_delay)park_locked(start_delay);pthread_mutex_unlock(&lock);
        return 0;
    }
    pthread_mutex_lock(&lock);helper_message=true;notify();while(!reply_sent && !helper_dead)park_locked(INT64_MAX);pthread_mutex_unlock(&lock);return reply_sent?0:5;
}
static int test_clock_gettime(int clock,struct timespec *ts){
    assert(clock==CLOCK_MONOTONIC);pthread_mutex_lock(&lock);
    if(scenario==5 && prepare_at<0){prepare_at=now_ms;pthread_mutex_unlock(&lock);errno=EIO;return -1;}
    if(prepare_at<0)prepare_at=now_ms;ts->tv_sec=now_ms/1000;ts->tv_nsec=(now_ms%1000)*1000000;pthread_mutex_unlock(&lock);return 0;
}
#define clock_gettime test_clock_gettime
static int test_usleep(unsigned us){pthread_mutex_lock(&lock);int64_t end=now_ms+us/1000;while(now_ms<end)park_locked(end);pthread_mutex_unlock(&lock);return 0;}
#define usleep test_usleep
static int proc_paused(pid_t p,bool *paused){assert(p==1);pthread_mutex_lock(&lock);if(prepare_at<0)prepare_at=now_ms;*paused=target_paused;pthread_mutex_unlock(&lock);return 0;}
static int roothide_patch_proc(pid_t p){
    assert(p==1);pthread_mutex_lock(&lock);patches++;patch_at=now_ms;
    int64_t end=now_ms+callback_delay;while(now_ms<end)park_locked(end);pthread_mutex_unlock(&lock);return 0;
}
static int test_kill(pid_t p,int sig){
    pthread_mutex_lock(&lock);
    if(p==1){assert(sig==SIGCONT);resumes++;if(scenario==6){pthread_mutex_unlock(&lock);errno=EPERM;return -1;}target_resumed=true;target_paused=false;notify();}
    else {assert(p==123 && sig==SIGKILL);helper_killed=true;notify();}
    pthread_mutex_unlock(&lock);return 0;
}
#define kill test_kill
static pid_t test_waitpid(pid_t p,int *status,int flags){
    assert(p==123 && flags==WNOHANG);*status=0;pthread_mutex_lock(&lock);helper_waits++;bool dead=helper_dead;if(dead)child_reaped++;pthread_mutex_unlock(&lock);return dead?p:0;
}
#define waitpid test_waitpid
static int posix_spawnattr_init(posix_spawnattr_t *a){*a=(void*)1;return 0;}
static int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *a,mach_port_t *p,uint32_t n){(void)a;assert(n==3 && p[2]==101);return 0;}
static int posix_spawnattr_destroy(posix_spawnattr_t *a){(void)a;return 0;}
static int helper_entry(int argc,char **argv);
static void *run_helper(void *unused){(void)unused;role=1;int r=helper_entry(0,NULL);exit_helper(r);return NULL;}
static int test_spawn(pid_t *p,const char *path,const void *actions,const posix_spawnattr_t *a,char *const argv[],char *const env[]){
    (void)path;(void)actions;(void)a;(void)argv;(void)env;*p=123;
    pthread_mutex_lock(&lock);helper_started=true;pthread_mutex_unlock(&lock);assert(!pthread_create(&helper_thread,NULL,run_helper,NULL));return 0;
}
#define posix_spawn test_spawn
static int test_setenv(const char *k,const char *v,int overwrite){(void)overwrite;assert(!strcmp(k,"BOOMERANG_PID"));snprintf(saved_pid,sizeof(saved_pid),"%s",v);return 0;}
#define setenv test_setenv
static const char *test_getenv(const char *k){if(!strcmp(k,"STAGED_JAILBREAK_UPDATE"))return "/fixture/update.tar";return saved_pid[0]?saved_pid:NULL;}
#define getenv test_getenv
static int test_unsetenv(const char *k){(void)k;return 0;}
#define unsetenv test_unsetenv
static int _NSGetExecutablePath(char *p,uint32_t *size){(void)size;strcpy(p,"/sbin/launchd");return 0;}
static int unmount(const char *p,int f){(void)p;(void)f;return 0;}
static int jbupdate_basebin(const char *p){(void)p;pthread_mutex_lock(&lock);int64_t end=done_at+update_delay;while(now_ms<end)park_locked(end);pthread_mutex_unlock(&lock);return 0;}
#define abort_with_reason(a,b,c,d) assert(!"unexpected update failure")
struct _posix_spawn_args_desc {int unused;};
static int __posix_spawn_orig_wrapper(pid_t *p,const char *path,struct _posix_spawn_args_desc *d,char *const a[],char *const e[]){
    (void)p;(void)path;(void)d;(void)a;(void)e;pthread_mutex_lock(&lock);setexec_seen=true;setexec_dead=helper_dead;target_paused=true;notify();pthread_mutex_unlock(&lock);return 700;
}
/* PRODUCTION */
static void *run_old(void *unused){
    (void)unused;role=0;struct _posix_spawn_args_desc d={0};pid_t p=1;
    int result=__posix_spawn_hook(&p,"/sbin/launchd",&d,NULL,NULL);
    pthread_mutex_lock(&lock);old_result=result;finished[0]=true;notify();pthread_mutex_unlock(&lock);return NULL;
}
int main(int argc,char **argv){
    assert(argc==2);scenario=atoi(argv[1]);update_delay=1000;
    if(scenario==1)update_delay=9800;
    if(scenario==2)update_delay=11000;
    if(scenario==7){start_delay=9000;update_delay=18500;}
    if(scenario==8)callback_delay=20000;
    if(scenario==9)update_delay=9950;
    main_queue.refs=100;
    pthread_t old;assert(!pthread_create(&old,NULL,run_old,NULL));
    pthread_mutex_lock(&lock);
    unsigned iterations=0;
    while(!(finished[0] && helper_started && finished[1])){
        if(helper_serving && finished[0] && target_resumed){
            /* Simulate the new launchd's final recovery DONE; no real RPC. */
            registered_helper=false;helper_message=true;notify();
        }
        bool idle=(finished[0] || parked[0]) && (!helper_started || finished[1] || parked[1]);
        if(idle){
            int64_t next=INT64_MAX;
            for(int r=0;r<2;r++)if(!finished[r] && parked[r] && wake_at[r]<next)next=wake_at[r];
            if(next!=INT64_MAX && next>now_ms){now_ms=next;notify();}
            // Baseline ignores SIGCONT failure, enters its server and waits
            // forever while the target remains paused. Stop the inert model
            // only after recording this unsupported state; this is not recovery.
            if(next==INT64_MAX && helper_serving && target_paused){helper_killed=true;notify();}
        }
        if(++iterations>1000000 || now_ms>65000){fputs("HARNESS scheduler failed to quiesce\n",stderr);abort();}
        pthread_cond_wait(&changed,&lock);
    }
    pthread_mutex_unlock(&lock);pthread_join(old,NULL);pthread_join(helper_thread,NULL);
    bool unsafe=setexec_seen && (setexec_dead || (helper_result!=0 && !target_resumed));
    printf("{\"scenario\":%d,\"done_ms\":%lld,\"prepare_ms\":%lld,\"patch_ms\":%lld,\"exit_ms\":%lld,"
           "\"old_result\":%d,\"helper_result\":%d,\"setexec\":%s,\"setexec_with_dead_helper\":%s,"
           "\"target_paused\":%s,\"resumes\":%d,\"old_receive_live\":%s,\"helper_receive_live\":%s,"
           "\"registered_helper_slot\":%s,\"unsafe\":%s}\n",
           scenario,(long long)done_at,(long long)prepare_at,(long long)patch_at,(long long)exit_at,
           old_result,helper_result,setexec_seen?"true":"false",setexec_dead?"true":"false",
           target_paused?"true":"false",resumes,old_port?"true":"false",helper_port?"true":"false",
           registered_helper?"true":"false",unsafe?"true":"false");
    return 0;
}
