// SPDX-License-Identifier: GPL-2.0
// swapevict.c — trace swap read/write per PID (watchdog)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct swap_val {
    __u64 read_pages;
    __u64 write_pages;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct swap_val);
} swap_accum SEC(".maps");

SEC("kprobe/swap_readpage")
int BPF_KPROBE(handle_swap_readpage)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct swap_val *val = bpf_map_lookup_elem(&swap_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->read_pages, 1);
    } else {
        struct swap_val new_val = { .read_pages = 1, .write_pages = 0 };
        bpf_map_update_elem(&swap_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

SEC("kprobe/swap_writepage")
int BPF_KPROBE(handle_swap_writepage)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct swap_val *val = bpf_map_lookup_elem(&swap_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->write_pages, 1);
    } else {
        struct swap_val new_val = { .read_pages = 0, .write_pages = 1 };
        bpf_map_update_elem(&swap_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
