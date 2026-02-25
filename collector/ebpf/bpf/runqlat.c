// SPDX-License-Identifier: GPL-2.0
// runqlat.c — trace run queue latency per PID (watchdog)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct rqlat_val {
    __u64 total_ns;
    __u32 count;
    __u32 max_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} rq_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct rqlat_val);
} rqlat_accum SEC(".maps");

// tracepoint/sched/sched_wakeup format:
//   char comm[16], pid_t pid, int prio, int target_cpu
struct sched_wakeup_args {
    unsigned long long unused;
    char comm[16];
    int pid;
    int prio;
    int target_cpu;
};

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct sched_wakeup_args *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    if (pid == 0)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&rq_start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sched_switch")
int handle_sched_switch_rqlat(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    __u32 pid = BPF_CORE_READ(next, tgid);
    if (pid == 0)
        return 0;

    __u64 *tsp = bpf_map_lookup_elem(&rq_start, &pid);
    if (!tsp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&rq_start, &pid);

    // Skip stale entries > 10s
    if (delta > 10000000000ULL)
        return 0;

    struct rqlat_val *val = bpf_map_lookup_elem(&rqlat_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->total_ns, delta);
        __sync_fetch_and_add(&val->count, 1);
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        if (delta32 > val->max_ns)
            val->max_ns = delta32;
    } else {
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        struct rqlat_val new_val = {
            .total_ns = delta,
            .count = 1,
            .max_ns = delta32,
        };
        bpf_map_update_elem(&rqlat_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
