# MediaTek CVE-2026-43499 Port Analysis

## Summary of Findings from Reference Repositories

### 1. Aristotle Repository (MediaTek 5.10.136)
**URL:** https://github.com/soralis0912/CVE-2026-43499-aristotle/

**Key Differences from Qualcomm Kernels:**
1. **rt_mutex_waiter layout:** Old "flat" layout (10 words) vs 6.x (13 words with wake_state/ww_ctx)
2. **No xbl_config:** Uses dynamic KASLR bypass via kernel info-leak
3. **Physical constants:**
   - `P0_PHYS_OFFSET = 0x40000000` (1GB, from device tree)
   - `P0_KERNEL_PHYS_LOAD = 0x40000000` (delta = 0, kernel loads at PHYS_OFFSET)
4. **KIMAGE_TEXT_BASE:** `0xffffffc010000000` (different from our kernel)

### 2. Nord 2 Specific Issues

**Kernel Address Space:**
- Actual kernel base: `0xffffff9805280800`
- This is in LINEAR MAP region (`0xffffff80...` - `0xffffffc0...`)
- NOT in vmalloc region (`0xffffffc0...`) where most kernels are

**The Core Problem:**
1. Exploit's pselect slide technique returns addresses in `0xffffff80...` range
2. But the actual kernel is at `0xffffff98...`
3. The slide leak returns completely wrong addresses (gap of ~6GB)
4. All subsequent address calculations are wrong
5. Kernel writes to wrong addresses → crash

### 3. Root Cause Analysis

**Why the slide technique fails:**
1. The pselect slide uses `SLIDE_NFULNL_LOGGER` which is calculated via:
   ```c
   P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_IMAGE)
   = P0_PAGE_OFFSET | ((SLIDE_NFULNL_LOGGER_IMAGE - KIMAGE_TEXT_BASE) + P0_KERNEL_PHYS_DELTA)
   ```
2. This calculation assumes kernel is identity-mapped in linear space
3. But MediaTek 4.14 kernel is NOT identity-mapped at the expected location
4. The leaked address is from wrong memory region

**Memory Layout Difference:**

| Component | Aristotle (5.10) | Nord 2 (4.14) |
|-----------|------------------|---------------|
| KIMAGE_TEXT_BASE | 0xffffffc010000000 | 0xffffffc080000000 (wrong!) |
| Actual kernel | 0xffffffc010XXXXXX | 0xffffff9805280800 |
| Linear map base | 0xffffff8000000000 | 0xffffff8000000000 |
| PHYS_OFFSET | 0x40000000 | Unknown |

## Required Changes for Nord 2 Port

### Option A: Fix the KASLR Bypass (Recommended)

The pselect slide technique needs complete rewrite for this kernel:

1. **Leak actual kernel address** from pselect instead of fabricated one
2. **Calculate correct kernel base** from the leaked address
3. **Update all address calculations** to use correct offsets

### Option B: Use Different KASLR Bypass

Since pselect slide doesn't work, consider:
1. `/proc/kallsyms` leak (requires root, we don't have)
2. Other kernel info-leak techniques
3. Brute-force KASLR slide (slow, may trigger watchdog)

### Option C: Direct Symbol Address (Needs Verification)

If we can determine the exact KASLR slide, we could:
1. Calculate all target addresses directly
2. Skip the dynamic KASLR bypass entirely
3. Use hardcoded offsets for this specific kernel build

## Next Steps

1. **Analyze pselect slide code** to understand why it returns wrong addresses
2. **Check kernel memory map** on Nord 2 to understand actual layout
3. **Verify if KERNELSNITCH works** with correct address range
4. **Consider alternative exploit approach** for MediaTek 4.14

## Technical Details for Porting

### rt_mutex_waiter Layout (4.14 - same as 5.10)

```c
// 10-word flat layout (no wake_state/ww_ctx)
WAITER_TREE_ENTRY_OFF      0x00  // rb_node (24 bytes)
WAITER_PI_TREE_ENTRY_OFF   0x18  // rb_node (24 bytes)
WAITER_TASK_OFF            0x30  // task_struct*
WAITER_LOCK_OFF            0x38  // rt_mutex*
WAITER_PRIO_OFF            0x40  // int
WAITER_DEADLINE_OFF        0x48  // u64
// Total: 0x50 (80 bytes)
```

### MM_STRUCT Size

From `/proc/slabinfo`: 896 bytes (0x380)

### Key Offsets from Kallsyms

```
noop_llseek:      0x001fd140
cap_capable:      0x003cb62c
nfulnl_log_packet: 0x00ef0ab4
ashmem_ioctl:     0x00d8563c
```

### Target Addresses (Need to be calculated correctly)

```
selinux_enforcing: 0xffffff9806680800 (from kallsyms)
init_task:         Unknown (DATA symbol, not in kallsyms)
init_cred:         Unknown (DATA symbol, not in kallsyms)
```

## Conclusion

The current exploit cannot work on Nord 2 because:
1. KASLR bypass returns wrong addresses
2. Kernel is in unexpected memory region
3. All address calculations are based on wrong assumptions

**Recommendation:** Port the aristotle exploit code which is designed for MediaTek kernels, rather than trying to fix the Qualcomm-focused ghostlock exploit.
