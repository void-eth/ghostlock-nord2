// Simple program to find a safe kernel page using root access
// Run: su -c "cat /proc/kpageflags" to find usable pages

#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define KERNEL_START 0xffffff8008000000ULL
#define PAGE_SIZE 4096

int main() {
    // Try to read kernel memory via /dev/kmem or /proc/kcore
    // On rooted Android, we can use su to access these
    
    printf("Looking for safe kernel page...\n");
    
    // Check if /proc/kpageflags is accessible
    FILE *f = fopen("/proc/kpageflags", "r");
    if (f) {
        printf("kpageflags accessible!\n");
        fclose(f);
    }
    
    // Try /dev/kmem
    int fd = open("/dev/kmem", O_RDONLY);
    if (fd >= 0) {
        printf("kmem accessible!\n");
        close(fd);
    }
    
    return 0;
}
