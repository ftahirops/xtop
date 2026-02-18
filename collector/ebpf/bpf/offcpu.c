// SPDX-License-Identifier: GPL-2.0
// offcpu.c — trace INVOLUNTARY off-CPU time per PID via sched_switch
//
// Only tracks preemption (TASK_RUNNING) and uninterruptible sleep
// (TASK_UNINTERRUPTIBLE = IO wait, mutex, page fault).
// Voluntary sleep (TASK_INTERRUPTIBLE = poll, select, nanosleep) is skipped,
// since those processes aren't experiencing contention.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_INTERRUPTIBLE  1

struct offcpu_val {
    __u64 total_ns;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} offcpu_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct offcpu_val);
} offcpu_accum SEC(".maps");

SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];

    __u64 now = bpf_ktime_get_ns();
    __u32 prev_pid = BPF_CORE_READ(prev, tgid);
    __u32 next_pid = BPF_CORE_READ(next, tgid);

    // Record switch-out time for prev, but ONLY for involuntary off-CPU.
    // __state bits: 0=TASK_RUNNING (preempted), 1=TASK_INTERRUPTIBLE (voluntary),
    //               2=TASK_UNINTERRUPTIBLE (IO/mutex/D-state)
    // We skip TASK_INTERRUPTIBLE — processes that voluntarily slept (poll, select,
    // nanosleep, condwait) are NOT experiencing contention.
    if (prev_pid > 1) {
        unsigned int prev_state = BPF_CORE_READ(prev, __state) & 0xff;
        if (prev_state != TASK_INTERRUPTIBLE) {
            bpf_map_update_elem(&offcpu_start, &prev_pid, &now, BPF_ANY);
        }
    }

    // Compute off-CPU duration for next (only if we recorded a start)
    if (next_pid > 1) {
        __u64 *tsp = bpf_map_lookup_elem(&offcpu_start, &next_pid);
        if (tsp && *tsp > 0) {
            __u64 delta = now - *tsp;
            // Only count reasonable deltas (< 30s, avoids stale entries)
            if (delta < 30000000000ULL) {
                struct offcpu_val *val = bpf_map_lookup_elem(&offcpu_accum, &next_pid);
                if (val) {
                    __sync_fetch_and_add(&val->total_ns, delta);
                    __sync_fetch_and_add(&val->count, 1);
                } else {
                    struct offcpu_val new_val = { .total_ns = delta, .count = 1 };
                    bpf_map_update_elem(&offcpu_accum, &next_pid, &new_val, BPF_NOEXIST);
                }
            }
            bpf_map_delete_elem(&offcpu_start, &next_pid);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
