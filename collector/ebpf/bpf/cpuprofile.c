// SPDX-License-Identifier: GPL-2.0
// CPU profile stack sampler for flamegraph generation.
// Attaches to perf_event (PERF_COUNT_SW_CPU_CLOCK at 99Hz) and captures
// user+kernel stack traces per-PID.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 127
#define MAX_ENTRIES     10240

struct key_t {
    __u32 pid;
    __s32 user_stack_id;
    __s32 kern_stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct key_t));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

// Target PID filter (0 = all)
const volatile __u32 target_pid = 0;

SEC("perf_event")
int cpu_profile(struct bpf_perf_event_data *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Filter by target PID if set
    if (target_pid > 0 && pid != target_pid)
        return 0;

    // Skip kernel threads
    if (pid == 0)
        return 0;

    struct key_t key = {};
    key.pid = pid;
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    key.kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

    __u64 *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&counts, &key, &one, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
