// SPDX-License-Identifier: GPL-2.0
// pgfault.c — trace page fault latency per PID (watchdog)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define VM_FAULT_MAJOR 0x0004

struct pgfault_val {
    __u64 total_ns;
    __u32 count;
    __u32 major_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} pgfault_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct pgfault_val);
} pgfault_accum SEC(".maps");

// handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
//                 unsigned int flags, struct pt_regs *regs)
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_fault_enter)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&pgfault_start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(handle_fault_exit, long ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 *tsp = bpf_map_lookup_elem(&pgfault_start, &pid);
    if (!tsp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&pgfault_start, &pid);

    // Skip stale > 5s
    if (delta > 5000000000ULL)
        return 0;

    int is_major = (ret & VM_FAULT_MAJOR) ? 1 : 0;

    struct pgfault_val *val = bpf_map_lookup_elem(&pgfault_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->total_ns, delta);
        __sync_fetch_and_add(&val->count, 1);
        if (is_major)
            __sync_fetch_and_add(&val->major_count, 1);
    } else {
        struct pgfault_val new_val = {
            .total_ns = delta,
            .count = 1,
            .major_count = is_major ? 1 : 0,
        };
        bpf_map_update_elem(&pgfault_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
