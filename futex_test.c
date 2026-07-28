#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdatomic.h>
#include <errno.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

static uint32_t futex = 0;
static atomic_int owner_ready = 0;

void *owner_fn(void *arg) {
    long ret = syscall(SYS_futex, &futex, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] locked: ret=%ld, futex=%u, tid=%d\n", ret, futex, gettid());
    atomic_store(&owner_ready, 1);
    sleep(5);
    ret = syscall(SYS_futex, &futex, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[owner] unlocked: ret=%ld\n", ret);
    return NULL;
}

int main(void) {
    printf("=== Basic FUTEX_PI test ===\n");
    
    pthread_t owner;
    pthread_create(&owner, NULL, owner_fn, NULL);
    while (!atomic_load(&owner_ready)) sched_yield();
    usleep(100000);
    
    printf("[main] trying to lock (should block until owner unlocks)...\n");
    long ret = syscall(SYS_futex, &futex, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[main] lock ret=%ld errno=%d futex=%u\n", ret, errno, futex);
    
    pthread_join(owner, NULL);
    printf("[main] done\n");
    return 0;
}
