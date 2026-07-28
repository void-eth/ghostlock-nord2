# GitHub Issues Analysis Summary

## Key Findings from GitHub Issues

### 1. duchamp-root Issue #1: "slide bad leaked pointer"
**URL:** https://github.com/Colorful-glassblock/duchamp-root/issues/1

**Problem:** Redmi K70E (kernel 6.1.138) fails with:
```
[*] slide pselect returned ret=0 errno=0 calls=1 sched_ok=0 last_sched_ret=-1 last_sched_errno=0
[-] slide bad leaked pointer=92421739d676426e
```

**Root cause:** The pselect slide technique returns garbage values (non-kernel addresses). This is the **EXACT SAME PROBLEM** we are seeing on Nord 2.

**Status:** Issue closed but no clear solution posted.

---

### 2. CyberMeowfia Issue #7: MediaTek Rust Ashmem
**URL:** https://github.com/NebuSec/CyberMeowfia/issues/7

**Problem:** "Some symbols, such as 'ashmem_misc', can't be found on the kernel of Qualcomm and MediaTek equipment."

**Key insight:** MediaTek devices use **Rust ashmem** instead of C ashmem:
```
ffffffc080efb1a0 T _RNvXs1_NtCs232Q5cNN6Ho_11ashmem_rust15ashmem_shrinker...
```

The exploit needs to find alternative symbols for Rust ashmem devices.

---

### 3. CyberMeowfia Issue #63: 4.14 Kernel Support
**URL:** https://github.com/NebuSec/CyberMeowfia/issues/63

**Question:** "Can you please add 4.14 kernel support?"

**Answer:** "Did you not read this exploit supports all the way down to 2.6"

**Key insight:** The exploit claims to support 4.14, but that doesn't mean it works out of the box on every 4.14 device. MediaTek memory layout differences are the real blocker.

---

### 4. CyberMeowfia Issue #45: Community Discussion
**URL:** https://github.com/NebuSec/CyberMeowfia/issues/45

**Key comments:**

1. **@JumboMite:** "I've seen a handful of people get the exploit chain to work on kernel 5.15+, and no examples of success on kernel 5.10 and older."
   - Confirms that older kernels (5.10 and below) have significant challenges

2. **@cgluWxh:** "Do you have any guidance for Android devices where the C ashmem implementation has been replaced by the Rust ashmem implementation?"
   - This is the MediaTek/Rust ashmem problem

3. **@Dere3046:** Links to [ElevateMe](https://github.com/Dere3046/ElevateMe) as a possible Rust ashmem solution

---

### 5. aristotle Repository (MediaTek 5.10)
**URL:** https://github.com/soralis0912/CVE-2026-43499-aristotle/

**Key findings:**
- Successfully ported to MediaTek 5.10.136
- Uses flat 10-word rt_mutex_waiter layout (no wake_state/ww_ctx)
- Uses dynamic KASLR bypass (no xbl_config)
- `KIMAGE_TEXT_BASE = 0xffffffc010000000`
- `P0_PHYS_OFFSET = 0x40000000`
- Kernel in linear map at expected location

**Critical differences from our Nord 2:**
- Nord 2 kernel at `0xffffff9805280800` (NOT at expected linear map location)
- The pselect slide technique may not work on 4.14 MediaTek

---

## Summary of Known Issues

| Problem | Devices Affected | Root Cause | Solution Status |
|---------|------------------|------------|-----------------|
| "slide bad leaked pointer" | Redmi K70E, Nord 2 | pselect returns garbage | **UNSOLVED** |
| Rust ashmem symbols missing | MediaTek devices | Rust replaces C ashmem | Alternative symbols needed |
| Kernel 5.10 and older | Various | Memory layout differences | Partial (aristotle for 5.10) |
| Kernel panic on select() | Nord 2 | Wrong target addresses | KASLR bypass broken |

---

## Actionable Next Steps

### For Nord 2 (MediaTek 4.14):

1. **Try aristotle's approach:**
   - Port aristotle code which is designed for MediaTek
   - Use dynamic KASLR bypass
   - Adjust for 4.14-specific offsets

2. **Alternative KASLR bypass:**
   - If pselect slide doesn't work, need different method
   - Consider perf_event_open fallback (like duchamp PR #11)
   - Or direct calculation from rooted kallsyms

3. **Rust ashmem handling:**
   - Check if Nord 2 uses Rust ashmem
   - Find alternative symbols if needed
   - May need to use different fops targets

4. **Memory layout investigation:**
   - Understand why kernel is at `0xffffff98...` instead of expected location
   - This may be 4.14-specific MediaTek behavior
   - May require different address calculation entirely

---

## Recommended Approach

Given the findings:

1. **Clone aristotle exploit** - It's specifically designed for MediaTek
2. **Adjust for 4.14** - Modify waiter layout and offsets for 4.14
3. **Use rooted kallsyms** - Calculate correct KASLR slide directly
4. **Test pselect slide** - If it fails, implement perf fallback
5. **Handle Rust ashmem** - If Nord 2 uses it, find alternative symbols

The aristotle repository is the most promising starting point because:
- It's designed for MediaTek (not Qualcomm)
- Uses dynamic KASLR bypass
- Has 5.10 flat waiter layout (similar to 4.14)
- Successfully handles MediaTek memory quirks
