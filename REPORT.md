# GhostLock OnePlus Nord 2 Port - Status Report

## Current State

The exploit chain is working up to the UAF trigger, but the kernel read primitive is failing.

### What Works
1. **KASLR leak via perf_event_init_task** - Gets correct slide every time
2. **Key drain** - 6500/6500 keys successfully allocated
3. **Thread setup** - owner and waiter threads start correctly
4. **UAF trigger** - `FUTEX_CMP_REQUEUE_PI ret=1` confirms waiter freed
5. **Key reclamation** - Key lands in freed slot

### What's Broken
**Kernel read primitive** - The pselect-based read returns zeros:
```
PERCPU: base=ffffff82ba0dde58 offset[7]=0000000000000000
CURRENT_TASK: slot=ffffff82ba078070 value=0000000000000000
fake_task=0000000000000000
```

This means:
- Cannot get `main_task` (current task_struct)
- Cannot do EDEADLK confirmation test
- Cannot read init_task->prio for offset detection

### Root Cause Analysis

The `direct_read_shape0_exact64_once` function uses pselect to read kernel memory:
1. Pins to CPU 7
2. Writes to a kernel address via pselect timing race
3. Reads back via /proc/sys/kernel/random/boot_id

The read shows `offset[7]=0` which means either:
- The pselect timing missed on this specific kernel
- CPU migration happened during the read
- The kernel's direct map is configured differently

### Code Path Analysis

```
preload.so → direct_root_begin → direct_read_shape0_exact64_once(percpu_slot)
           → direct_pselect_write_once(B=boot_id_data, Q=percpu_slot)
           → pselect race to read *(percpu_slot) via boot_id
           → Result: 0x0000000000000000
```

### What We Need

To proceed with the EDEADLK confirmation test, we need one of:

1. **Working pselect read** - Debug why it returns 0
2. **Alternative read primitive** - msg_msg OOB read, or other method
3. **Brute force with timing** - Skip the read, try all offsets

### The Original GhostLock Approach

The reference implementation:
1. Uses the same pselect read primitive
2. Has complex timing loops and CPU affinity
3. Works on Pixel 6 with kernel 5.10

OnePlus Nord 2 differences:
- MediaTek MT6893 vs Google Tensor
- Kernel 4.14.186 vs 5.10
- Different scheduler behavior
- Possible hardening in oplus-specific code

### Next Steps Options

**Option A: Debug pselect read**
- Add more timing calibration
- Try different CPU cores
- Check for kernel hardening that blocks the race

**Option B: Use msg_msg OOB read**
- msg_msg can be used for kernel heap read
- Requires different spray technique
- More reliable on older kernels

**Option C: Blind brute force**
- Try all offsets without read verification
- Use EDEADLK as the detection (no timing needed)
- ~50 offsets to try, one should work

**Option D: Analyze kernel diff**
- Compare OnePlus kernel to stock 4.14
- Look for hardening that breaks the primitive
- May reveal why pselect read fails

## Technical Details

### Key Offsets (from vmlinux disassembly)
```
PER_CPU_OFFSET:  0xffffff80096dde58
ENTRY_TASK:      0xffffff8009878070
INIT_CRED:       0xffffff8009d89fc8
FAKE_LOCK:       0xffffff8009d6d000 (BSS)
INIT_TASK:       0xffffff800957b6c0
```

### rt_mutex_waiter Offsets (key payload)
```
payload + 30: waiter->task (8 bytes)
payload + 38: waiter->lock (8 bytes)
payload + 46: waiter->prio (4 bytes)
```

### Chain Walk Path
```
FUTEX_LOCK_PI(f_waiter_owns)
  → f_waiter_owns owned by waiter_thread
  → rt_mutex_adjust_prio_chain(waiter_thread)
  → reads waiter_thread->pi_blocked_on  ← UAF freed slot
  → reads fake_waiter->lock (fake_lock)
  → reads fake_lock->owner
  → if owner == current: EDEADLK
  → else: rt_mutex_setprio(fake_waiter->task, prio)
```

## Recommendation

The pselect read primitive failure is the critical blocker. Without kernel memory read, we cannot:
1. Get main_task for EDEADLK test
2. Read init_task->prio to verify writes
3. Scan for self-referential pointers

Focus on either fixing the read primitive or implementing an alternative (msg_msg OOB read).
