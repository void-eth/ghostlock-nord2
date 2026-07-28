#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <errno.h>

#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#define __INTEL
#endif

#define RDPRU ".byte 0x0f, 0x01, 0xfd"
#define RDPRU_ECX_MPERF 0
#define RDPRU_ECX_APERF 1

// Thread-local perf event FD
static __thread int perf_fd = -1;

static inline void init_perf_fd(void) {
    if (perf_fd >= 0) return;
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;
    perf_fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (perf_fd < 0) {
        // Fallback to virtual counter
        perf_fd = -2;
    }
}

static inline size_t rdtsc_begin(void) {
#if defined(__INTEL)
    size_t a, d;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("lfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("mfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("lfence");
    return aval;
#elif defined(__ARM)
    init_perf_fd();
    if (perf_fd >= 0) {
        long long value = 0;
        read(perf_fd, &value, sizeof(value));
        return (size_t)value;
    } else {
        // Fallback to virtual counter
        unsigned long long vct;
        asm volatile("isb" ::: "memory");
        asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
        asm volatile("isb" ::: "memory");
        return (size_t)vct;
    }
#else
#error "Invalid TIMEUTILS_ARCH value"
#endif
}

static inline size_t rdtsc_end(void) {
#if defined(__INTEL)
    size_t a, d;
    asm volatile("lfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("lfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("mfence");
    return aval;
#elif defined(__ARM)
    init_perf_fd();
    if (perf_fd >= 0) {
        long long value = 0;
        read(perf_fd, &value, sizeof(value));
        return (size_t)value;
    } else {
        unsigned long long vct;
        asm volatile("isb" ::: "memory");
        asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
        asm volatile("isb" ::: "memory");
        return (size_t)vct;
    }
#else
#error "Invalid TIMEUTILS_ARCH value"
#endif
}
