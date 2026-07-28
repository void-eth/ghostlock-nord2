// patch_oplus.c - Patch oplus security hooks to prevent reboot
// Compile: aarch64-linux-gnu-gcc -static -o patch_oplus patch_oplus.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <oplus_root_check_addr> <oplus_root_reboot_addr>\n", argv[0]);
        printf("Get addresses from: cat /proc/kallsyms | grep oplus_root\n");
        return 1;
    }
    
    uint64_t addrs[2] = { 
        strtoull(argv[1], NULL, 16), 
        strtoull(argv[2], NULL, 16) 
    };
    const char *names[2] = { "oplus_root_check", "oplus_root_reboot" };
    uint32_t ret_insn = 0xd65f03c0;  // ARM64 RET instruction

    int fd = open("/dev/kmem", O_RDWR | O_SYNC);
    if (fd < 0) { 
        perror("open /dev/kmem - need root and Magisk kmem module");
        return 1; 
    }

    printf("[*] Opened /dev/kmem successfully\n");
    
    for (int i = 0; i < 2; i++) {
        uint32_t orig = 0, verify = 0;
        
        // Read original
        lseek(fd, (off_t)addrs[i], SEEK_SET);
        read(fd, &orig, 4);
        
        // Write RET
        lseek(fd, (off_t)addrs[i], SEEK_SET);
        write(fd, &ret_insn, 4);
        
        // Verify
        lseek(fd, (off_t)addrs[i], SEEK_SET);
        read(fd, &verify, 4);
        
        printf("[%c] %s @ %lx: %08x -> %08x %s\n",
               verify == ret_insn ? '+' : '-',
               names[i], 
               (unsigned long)addrs[i], 
               orig, verify,
               verify == ret_insn ? "PATCHED" : "FAILED");
    }
    
    close(fd);
    printf("[+] Done - oplus hooks neutralized\n");
    return 0;
}
