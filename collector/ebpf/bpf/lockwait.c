// SPDX-License-Identifier: GPL-2.0
// lockwait.c — trace futex wait contention per PID
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// futex ops we care about
#define FUTEX_WAIT          0
#define FUTEX_WAIT_BITSET   9
#define FUTEX_LOCK_PI       6

struct lock_val {
    __u64 total_wait_ns;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} futex_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct lock_val);
} futex_accum SEC(".maps");

// tracepoint/syscalls/sys_enter_futex args:
// int __syscall_nr, u32 *uaddr, int op, u32 val, ...
struct sys_enter_futex_args {
    unsigned long long unused;
    long syscall_nr;
    long uaddr;
    long op;
    long val;
};

struct sys_exit_futex_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_enter_futex")
int handle_futex_enter(struct sys_enter_futex_args *ctx)
{
    int op = (int)(ctx->op & 0x7F); // mask out FUTEX_PRIVATE_FLAG etc.
    if (op != FUTEX_WAIT && op != FUTEX_WAIT_BITSET && op != FUTEX_LOCK_PI)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&futex_start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int handle_futex_exit(struct sys_exit_futex_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 *tsp = bpf_map_lookup_elem(&futex_start, &pid);
    if (!tsp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&futex_start, &pid);

    if (delta == 0 || delta > 30000000000ULL) // skip >30s stale
        return 0;

    struct lock_val *val = bpf_map_lookup_elem(&futex_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->total_wait_ns, delta);
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct lock_val new_val = { .total_wait_ns = delta, .count = 1 };
        bpf_map_update_elem(&futex_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
