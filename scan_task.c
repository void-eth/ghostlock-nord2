// scan_task.c - Scan init_task for pointer fields
// Compile: aarch64-linux-gnu-gcc -static -o scan_task scan_task.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

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
    
    if (slide == 0) {
        printf("[-] Could not find KASLR slide\n");
        return 1;
    }
    printf("[*] slide = %lx\n", slide);
    
    uint64_t init_task_static  = 0xffffff800957b6c0ULL;  // From vmlinux
    uint64_t init_task_runtime = init_task_static + slide;
    printf("[*] init_task runtime = %lx\n", init_task_runtime);
    
    // Read via /proc/kcore
    int fd = open("/proc/kcore", O_RDONLY);
    if (fd < 0) { 
        perror("kcore"); 
        printf("[-] /proc/kcore not available\n");
        return 1; 
    }
    
    // Read ELF header (64-bit)
    unsigned char ehdr[64];
    read(fd, ehdr, 64);
    
    uint64_t phoff   = *(uint64_t*)(ehdr + 0x28);
    uint16_t phnum   = *(uint16_t*)(ehdr + 0x38);
    uint16_t phentsize = *(uint16_t*)(ehdr + 0x36);
    
    printf("[*] kcore: %d program headers, phoff=%lx\n", phnum, phoff);
    
    // Find segment containing init_task
    for (int i = 0; i < phnum; i++) {
        uint8_t phdr[56];
        lseek(fd, phoff + i * phentsize, SEEK_SET);
        read(fd, phdr, 56);
        
        uint32_t ptype  = *(uint32_t*)(phdr + 0);
        uint64_t offset = *(uint64_t*)(phdr + 0x08);
        uint64_t vaddr  = *(uint64_t*)(phdr + 0x10);
        uint64_t filesz = *(uint64_t*)(phdr + 0x20);
        
        printf("[*] Segment %d: type=%u vaddr=%lx filesz=%lx\n", i, ptype, vaddr, filesz);
        
        if (ptype == 1 && vaddr <= init_task_runtime && init_task_runtime < vaddr + filesz) {
            uint64_t file_off = offset + (init_task_runtime - vaddr);
            lseek(fd, file_off, SEEK_SET);
            
            printf("[+] Found init_task in segment %d\n", i);
            printf("[+] Scanning init_task pointer fields:\n");
            
            uint64_t buf[128];
            read(fd, buf, 1024);
            
            for (int j = 0; j < 128; j++) {
                // Print pointer-like values (kernel addresses)
                if ((buf[j] >> 40) == (init_task_runtime >> 40) && buf[j] != 0) {
                    printf("  init_task+0x%03x = %lx", j*8, buf[j]);
                    if (buf[j] == init_task_runtime)
                        printf("  <- SELF (real_parent or group_leader)");
                    printf("\n");
                }
            }
            break;
        }
    }
    close(fd);
    return 0;
}
