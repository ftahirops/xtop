// SPDX-License-Identifier: GPL-2.0
// syscalldissect.c — per-PID syscall time profiling via raw_syscalls
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct sc_key {
    __u32 pid;
    __u32 syscall_nr;
};

struct sc_val {
    __u64 total_ns;
    __u32 count;
    __u32 max_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} sc_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct sc_key);
    __type(value, struct sc_val);
} sc_accum SEC(".maps");

// raw_syscalls/sys_enter args: long id, unsigned long args[6]
struct sys_enter_args {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

// raw_syscalls/sys_exit args: long id, long ret
struct sys_exit_args {
    unsigned long long unused;
    long id;
    long ret;
};

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&sc_start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct sys_exit_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 *tsp = bpf_map_lookup_elem(&sc_start, &pid);
    if (!tsp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&sc_start, &pid);

    // Skip stale entries > 30s
    if (delta > 30000000000ULL)
        return 0;

    __u32 nr = (__u32)ctx->id;
    struct sc_key key = { .pid = pid, .syscall_nr = nr };

    struct sc_val *val = bpf_map_lookup_elem(&sc_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->total_ns, delta);
        __sync_fetch_and_add(&val->count, 1);
        // max_ns is racy on SMP but only informational
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        if (delta32 > val->max_ns)
            val->max_ns = delta32;
    } else {
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        struct sc_val new_val = {
            .total_ns = delta,
            .count = 1,
            .max_ns = delta32,
        };
        bpf_map_update_elem(&sc_accum, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
