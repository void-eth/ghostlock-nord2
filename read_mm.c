// Helper to read mm_struct from kernel memory using root access
// This uses /dev/kmem or similar interfaces

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// From our vmlinux analysis
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
#define INIT_TASK_OFF    0x157b6c0ULL  // Static offset from vmlinux
#define INIT_CRED_OFF    0x1d89fc8ULL
#define TASK_MM_OFF      0x560ULL

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <kaslr_slide_hex>\n", argv[0]);
        fprintf(stderr, "Example: %s 0x1c45c00000\n", argv[0]);
        return 1;
    }
    
    uint64_t slide = strtoull(argv[1], NULL, 0);
    
    uint64_t kernel_base = KIMAGE_TEXT_BASE + slide;
    uint64_t init_task = KIMAGE_TEXT_BASE + INIT_TASK_OFF + slide;
    uint64_t init_cred = KIMAGE_TEXT_BASE + INIT_CRED_OFF + slide;
    
    printf("KASLR slide:  %016llx\n", (unsigned long long)slide);
    printf("Kernel base:  %016llx\n", (unsigned long long)kernel_base);
    printf("init_task:    %016llx\n", (unsigned long long)init_task);
    printf("init_cred:    %016llx\n", (unsigned long long)init_cred);
    printf("\n");
    
    // The mm_struct of init (PID 1) should be at init_task + TASK_MM_OFF
    // But init task has no mm (it's a kernel thread), so we need our own process
    
    printf("To read mm_struct, we need:\n");
    printf("1. Our task_struct address (from per_cpu_offset)\n");
    printf("2. Read task_struct->mm at offset 0x560\n");
    printf("\n");
    printf("Since the device is rooted, we can try reading via /dev/kmem\n");
    
    // Try /dev/kmem
    int fd = open("/dev/kmem", O_RDONLY);
    if (fd >= 0) {
        printf("/dev/kmem is accessible!\n");
        close(fd);
    } else {
        printf("/dev/kmem not available: %s\n", strerror(errno));
    }
    
    return 0;
}
