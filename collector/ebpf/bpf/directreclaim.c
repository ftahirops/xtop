// SPDX-License-Identifier: GPL-2.0
// directreclaim.c — trace direct reclaim stall duration per PID (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct reclaim_val {
    __u64 stall_ns;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} reclaim_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct reclaim_val);
} reclaim_accum SEC(".maps");

// tracepoint/vmscan/mm_vmscan_direct_reclaim_begin format:
//   int order, gfp_t gfp_flags
struct vmscan_begin_args {
    unsigned long long unused;
    int order;
    unsigned int gfp_flags;
};

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int handle_reclaim_begin(struct vmscan_begin_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&reclaim_start, &pid, &ts, BPF_ANY);
    return 0;
}

// tracepoint/vmscan/mm_vmscan_direct_reclaim_end format:
//   unsigned long nr_reclaimed
struct vmscan_end_args {
    unsigned long long unused;
    unsigned long nr_reclaimed;
};

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int handle_reclaim_end(struct vmscan_end_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 *tsp = bpf_map_lookup_elem(&reclaim_start, &pid);
    if (!tsp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&reclaim_start, &pid);

    // Sanity: skip deltas > 30s
    if (delta > 30000000000ULL)
        return 0;

    struct reclaim_val *val = bpf_map_lookup_elem(&reclaim_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->stall_ns, delta);
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct reclaim_val new_val = { .stall_ns = delta, .count = 1 };
        bpf_map_update_elem(&reclaim_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
