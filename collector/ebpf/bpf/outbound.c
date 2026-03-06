// SPDX-License-Identifier: GPL-2.0
// outbound.c — outbound data volume tracker: per-PID per-dest TCP egress bytes (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct egress_key {
    __u32 pid;
    __u32 daddr;
};

struct egress_val {
    __u64 total_bytes;
    __u64 packet_count;
    __u64 last_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct egress_key);
    __type(value, struct egress_val);
} egress_accum SEC(".maps");

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg_egress, struct sock *sk, struct msghdr *msg, size_t size)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    if ((__s64)size <= 0)
        return 0;

    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    struct egress_key key = { .pid = pid, .daddr = daddr };

    struct egress_val *val = bpf_map_lookup_elem(&egress_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->total_bytes, (__u64)size);
        __sync_fetch_and_add(&val->packet_count, 1);
        val->last_ns = bpf_ktime_get_ns();
    } else {
        struct egress_val new_val = {
            .total_bytes = (__u64)size,
            .packet_count = 1,
            .last_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&egress_accum, &key, &new_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
