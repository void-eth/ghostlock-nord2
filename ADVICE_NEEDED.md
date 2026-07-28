# GhostLock Port to OnePlus Nord 2 - Advice Requested

## Current Status: Blocked by oplus_root_check Security Hook

### What Works
1. **KASLR leak via perf** - Successfully leaks kernel text base
2. **Key spray for kmalloc-128 reclamation** - 6500/6500 keys drained, reclaim key lands in freed slot
3. **UAF trigger** - FUTEX_CMP_REQUEUE_PI creates use-after-free condition
4. **Device survives UAF** - No kernel panic during race condition

### The Blocker
Device reboots silently during PI chain walk. Analysis indicates `oplus_root_check` hook in `__sched_setscheduler` detects the exploit and triggers `oplus_root_reboot`.

### Technical Details

#### Exploit Flow
```
1. Drain kmalloc-128 freelist with 6500 add_key() calls
2. Create rt_mutex_waiter via FUTEX_WAIT_REQUEUE_PI
3. Trigger UAF via FUTEX_CMP_REQUEUE_PI (frees waiter while still in PI chain)
4. Reclaim freed waiter slot with single key containing fake waiter data
5. Trigger PI chain walk via sched_setattr → oplus_root_check → REBOOT
```

#### The Problem
- `oplus_root_check` is hooked into `__sched_setscheduler`
- When PI chain is walked, `__sched_setscheduler` is called
- OnePlus security check detects suspicious state and reboots

#### Offsets (verified from vmlinux disassembly)
```
oplus_root_reboot:  0xffffff80090a0a58
oplus_root_check:   0xffffff80090a0e88
__sched_setscheduler: (contains call to oplus_root_check)
```

### Fake Waiter Structure
```c
// user_key_payload: 18 byte header + 110 byte data = 128 bytes (kmalloc-128)
// rt_mutex_waiter layout:
//   +0x30: task_struct *task
//   +0x38: rt_mutex *lock  
//   +0x40: int prio

// Key payload mapping (subtract 18 for header):
memcpy(payload + 30, &fake_task, 8);  // waiter->task
memcpy(payload + 38, &fake_lock, 8);  // waiter->lock
*(int*)(payload + 46) = 1;            // waiter->prio
```

### Attempted Solutions

#### 1. BSS Zero Page for fake_lock
- Points `fake_lock` to kernel BSS (all zeros)
- `lock->owner = 0` (NULL)
- Expected: kernel handles NULL owner gracefully
- Result: Device reboot (crash or oplus hook)

#### 2. ENTRY_TASK alias for fake_lock
- Points `fake_lock` to `ENTRY_TASK - 0x18`
- `lock->owner` reads from ENTRY_TASK (current task pointer)
- Expected: valid task_struct pointer
- Result: Not yet tested

### Questions for Claude

1. **Alternative PI chain walk trigger?**
   - `sched_setattr` calls `__sched_setscheduler` which triggers oplus_root_check
   - Is there another syscall that walks PI chain without going through `__sched_setscheduler`?
   - Options: `FUTEX_LOCK_PI`, `sched_setscheduler` (same path), others?

2. **Patching oplus_root_reboot without write primitive?**
   - Need to write RET instruction (0xd65f03c0) to oplus_root_reboot
   - No /dev/kmem available
   - Exploit gives write primitive AFTER PI chain walk (chicken-and-egg)
   - Any creative way to corrupt kernel code before exploit?

3. **Using fake_lock write to corrupt oplus_root_reboot?**
   - During PI chain walk, kernel might write to `lock->owner` or related fields
   - If we point `fake_lock` strategically, can we corrupt oplus_root_reboot?
   - What fields get written during `rt_mutex_adjust_prio_chain`?

4. **Is the crash actually from NULL owner or oplus hook?**
   - Device reboots silently (no kernel panic in dmesg)
   - Could be hardware watchdog or immediate reboot from oplus_root_reboot
   - How to distinguish?

5. **Alternative approaches for MediaTek/OnePlus?**
   - Different kernel primitive (msg_msg OOB read?)
   - Exploit other MediaTek-specific drivers?
   - Any known bypasses for oplus security hooks?

### Files Modified
- `/root/nord2-aristotle-port/src/util.c` - Key spray and grooming
- `/root/nord2-aristotle-port/src/main.c` - Key-based exploit path
- `/root/nord2-aristotle-port/src/target.h` - Offsets and constants
- `/root/nord2-aristotle-port/src/common.h` - Function declarations

### Key Constraints
- Device: OnePlus Nord 2 (DN2101), MediaTek MT6893
- Kernel: 4.14.186+ with OnePlus security patches
- Already rooted with Magisk (research device)
- SLAB_FREELIST_RANDOM=n, SLAB_FREELIST_HARDENED=n
- CONFIG_KEYS=y (add_key available)
