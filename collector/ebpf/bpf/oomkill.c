// SPDX-License-Identifier: GPL-2.0
// oomkill.c — trace OOM kill victim events (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct oom_val {
    __u64 ts;
    __u64 total_vm;
    __u64 anon_rss;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct oom_val);
} oom_accum SEC(".maps");

// tracepoint/oom/mark_victim format:
//   int pid
struct mark_victim_args {
    unsigned long long unused;
    int pid;
};

SEC("tracepoint/oom/mark_victim")
int handle_mark_victim(struct mark_victim_args *ctx)
{
    __u32 pid = (__u32)ctx->pid;

    struct oom_val val = {
        .ts = bpf_ktime_get_ns(),
        .total_vm = 0,
        .anon_rss = 0,
    };

    bpf_map_update_elem(&oom_accum, &pid, &val, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
