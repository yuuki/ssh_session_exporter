#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10

enum event_kind {
  EVENT_ACCEPT = 1,
  EVENT_FORK = 2,
  EVENT_EXEC = 3,
  EVENT_TTY_WRITE = 4,
  EVENT_EXIT = 5,
};

struct accept_args {
  __u64 upeer_sockaddr;
  __u64 upeer_addrlen;
};

struct event {
  __u8 kind;
  __u8 family;
  __u16 _pad;
  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u32 bytes;
  __u64 ts_ns;
  __u8 addr[16];
  char comm[TASK_COMM_LEN];
  char parent_comm[TASK_COMM_LEN];
};

struct trace_event_raw_sys_enter {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;
  __u8 common_preempt_lazy_count;
  __u8 __pad[3];
  __s32 id;
  unsigned long args[6];
};

struct trace_event_raw_sys_exit {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;
  __u8 common_preempt_lazy_count;
  __u8 __pad[3];
  __s32 id;
  long ret;
};

struct trace_event_raw_sched_process_fork {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;
  __u8 common_preempt_lazy_count;
  __u8 __pad[3];
  char parent_comm[TASK_COMM_LEN];
  __s32 parent_pid;
  char child_comm[TASK_COMM_LEN];
  __s32 child_pid;
};

struct trace_event_raw_sched_process_exec {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;
  __u8 common_preempt_lazy_count;
  __u8 __pad[3];
  __u32 filename_loc;
  __s32 pid;
  __s32 old_pid;
};

struct trace_event_raw_tty_write {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;
  __u8 common_preempt_lazy_count;
  __u8 __pad[3];
  __u64 tty;
  const char *buf;
  __u32 nr;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, struct accept_args);
} inflight_accepts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, __s64);
} inflight_writes SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int comm_is_sshd(const char comm[TASK_COMM_LEN]) {
  return comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd' && comm[4] == '\0';
}

static __always_inline int current_is_sshd(void) {
  char comm[TASK_COMM_LEN] = {};
  if (bpf_get_current_comm(comm, sizeof(comm)) != 0) {
    return 0;
  }
  return comm_is_sshd(comm);
}

static __always_inline int fill_addr(struct event *ev, const struct accept_args *args) {
  int addrlen = 0;
  __u16 family = 0;

  if (!args->upeer_sockaddr || !args->upeer_addrlen) {
    return 0;
  }
  if (bpf_probe_read_user(&addrlen, sizeof(addrlen), (const void *)args->upeer_addrlen) < 0) {
    return 0;
  }
  if (addrlen < sizeof(family)) {
    return 0;
  }
  if (bpf_probe_read_user(&family, sizeof(family), (const void *)args->upeer_sockaddr) < 0) {
    return 0;
  }

  ev->family = family;
  if (family == AF_INET_VALUE) {
    struct sockaddr_in sa = {};
    if (addrlen < sizeof(sa)) {
      return 0;
    }
    if (bpf_probe_read_user(&sa, sizeof(sa), (const void *)args->upeer_sockaddr) < 0) {
      return 0;
    }
    __builtin_memcpy(ev->addr, &sa.sin_addr, 4);
    return 1;
  }
  if (family == AF_INET6_VALUE) {
    struct sockaddr_in6 sa6 = {};
    if (addrlen < sizeof(sa6)) {
      return 0;
    }
    if (bpf_probe_read_user(&sa6, sizeof(sa6), (const void *)args->upeer_sockaddr) < 0) {
      return 0;
    }
    __builtin_memcpy(ev->addr, &sa6.sin6_addr, 16);
    return 1;
  }
  return 0;
}

static __always_inline void submit_event(const struct event *src) {
  struct event *dst;

  dst = bpf_ringbuf_reserve(&events, sizeof(*dst), 0);
  if (!dst) {
    return;
  }
  __builtin_memcpy(dst, src, sizeof(*dst));
  bpf_ringbuf_submit(dst, 0);
}

static __always_inline void fill_comm_from_exec_filename(char dst[TASK_COMM_LEN], const struct trace_event_raw_sched_process_exec *ctx) {
  __u16 offset = ctx->filename_loc & 0xffff;

  if (offset == 0) {
    return;
  }
  bpf_probe_read_kernel_str(dst, TASK_COMM_LEN, ((const char *)ctx) + offset);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct accept_args args = {};

  if (!current_is_sshd()) {
    return 0;
  }

  args.upeer_sockaddr = (__u64)ctx->args[1];
  args.upeer_addrlen = (__u64)ctx->args[2];
  bpf_map_update_elem(&inflight_accepts, &pid_tgid, &args, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_enter_accept(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct accept_args args = {};

  if (!current_is_sshd()) {
    return 0;
  }

  args.upeer_sockaddr = (__u64)ctx->args[1];
  args.upeer_addrlen = (__u64)ctx->args[2];
  bpf_map_update_elem(&inflight_accepts, &pid_tgid, &args, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct accept_args *args;
  struct event ev = {};

  if (ctx->ret < 0) {
    bpf_map_delete_elem(&inflight_accepts, &pid_tgid);
    return 0;
  }

  args = bpf_map_lookup_elem(&inflight_accepts, &pid_tgid);
  if (!args) {
    return 0;
  }

  ev.kind = EVENT_ACCEPT;
  ev.pid = pid_tgid >> 32;
  ev.ts_ns = bpf_ktime_get_ns();

  if (fill_addr(&ev, args)) {
    submit_event(&ev);
  }
  bpf_map_delete_elem(&inflight_accepts, &pid_tgid);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_exit_accept(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct accept_args *args;
  struct event ev = {};

  if (ctx->ret < 0) {
    bpf_map_delete_elem(&inflight_accepts, &pid_tgid);
    return 0;
  }

  args = bpf_map_lookup_elem(&inflight_accepts, &pid_tgid);
  if (!args) {
    return 0;
  }

  ev.kind = EVENT_ACCEPT;
  ev.pid = pid_tgid >> 32;
  ev.ts_ns = bpf_ktime_get_ns();

  if (fill_addr(&ev, args)) {
    submit_event(&ev);
  }
  bpf_map_delete_elem(&inflight_accepts, &pid_tgid);
  return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
  struct event ev = {};

  ev.kind = EVENT_FORK;
  ev.pid = ctx->child_pid;
  ev.ppid = ctx->parent_pid;
  ev.ts_ns = bpf_ktime_get_ns();
  __builtin_memcpy(ev.comm, ctx->child_comm, sizeof(ev.comm));
  __builtin_memcpy(ev.parent_comm, ctx->parent_comm, sizeof(ev.parent_comm));
  submit_event(&ev);
  return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
  struct event ev = {};

  ev.kind = EVENT_EXEC;
  ev.pid = ctx->pid;
  ev.uid = (__u32)bpf_get_current_uid_gid();
  ev.ts_ns = bpf_ktime_get_ns();
  fill_comm_from_exec_filename(ev.comm, ctx);
  if (ev.comm[0] == '\0') {
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
  }
  submit_event(&ev);
  return 0;
}

SEC("tracepoint/tty/tty_write")
int trace_tty_write(struct trace_event_raw_tty_write *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct event ev = {};

  ev.kind = EVENT_TTY_WRITE;
  ev.pid = pid_tgid >> 32;
  ev.uid = (__u32)bpf_get_current_uid_gid();
  ev.bytes = ctx->nr;
  ev.ts_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(ev.comm, sizeof(ev.comm));
  submit_event(&ev);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __s64 fd = (__s64)ctx->args[0];

  bpf_map_update_elem(&inflight_writes, &pid_tgid, &fd, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __s64 *fdp;
  struct event ev = {};

  if (ctx->ret <= 0) {
    bpf_map_delete_elem(&inflight_writes, &pid_tgid);
    return 0;
  }

  fdp = bpf_map_lookup_elem(&inflight_writes, &pid_tgid);
  if (!fdp) {
    return 0;
  }

  if (*fdp != 1 && *fdp != 2) {
    bpf_map_delete_elem(&inflight_writes, &pid_tgid);
    return 0;
  }

  ev.kind = EVENT_TTY_WRITE;
  ev.pid = pid_tgid >> 32;
  ev.uid = (__u32)bpf_get_current_uid_gid();
  ev.bytes = ctx->ret;
  ev.ts_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(ev.comm, sizeof(ev.comm));
  submit_event(&ev);
  bpf_map_delete_elem(&inflight_writes, &pid_tgid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_enter_writev(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __s64 fd = (__s64)ctx->args[0];

  bpf_map_update_elem(&inflight_writes, &pid_tgid, &fd, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int trace_exit_writev(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __s64 *fdp;
  struct event ev = {};

  if (ctx->ret <= 0) {
    bpf_map_delete_elem(&inflight_writes, &pid_tgid);
    return 0;
  }

  fdp = bpf_map_lookup_elem(&inflight_writes, &pid_tgid);
  if (!fdp) {
    return 0;
  }

  if (*fdp != 1 && *fdp != 2) {
    bpf_map_delete_elem(&inflight_writes, &pid_tgid);
    return 0;
  }

  ev.kind = EVENT_TTY_WRITE;
  ev.pid = pid_tgid >> 32;
  ev.uid = (__u32)bpf_get_current_uid_gid();
  ev.bytes = ctx->ret;
  ev.ts_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(ev.comm, sizeof(ev.comm));
  submit_event(&ev);
  bpf_map_delete_elem(&inflight_writes, &pid_tgid);
  return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct event ev = {};

  ev.kind = EVENT_EXIT;
  ev.pid = pid_tgid >> 32;
  ev.ts_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(ev.comm, sizeof(ev.comm));
  submit_event(&ev);
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
