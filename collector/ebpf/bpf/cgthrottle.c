// SPDX-License-Identifier: GPL-2.0
// cgthrottle.c — trace cgroup CPU throttle events (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct throttle_val {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct throttle_val);
} throttle_accum SEC(".maps");

// throttle_cfs_rq(struct cfs_rq *cfs_rq)
SEC("kprobe/throttle_cfs_rq")
int BPF_KPROBE(handle_throttle_cfs_rq)
{
    __u64 cgid = bpf_get_current_cgroup_id();

    struct throttle_val *val = bpf_map_lookup_elem(&throttle_accum, &cgid);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct throttle_val new_val = { .count = 1 };
        bpf_map_update_elem(&throttle_accum, &cgid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
