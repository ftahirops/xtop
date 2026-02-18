// SPDX-License-Identifier: GPL-2.0
// tcprtt.c — trace TCP RTT per remote endpoint
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct rtt_key {
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};

struct rtt_val {
    __u64 sum_us;
    __u32 count;
    __u32 min_us;
    __u32 max_us;
    __u32 last_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct rtt_key);
    __type(value, struct rtt_val);
} rtt_accum SEC(".maps");

// tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(handle_tcp_rcv_established, struct sock *sk)
{
    // Read smoothed RTT from tcp_sock (srtt_us is in units of 8us)
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u32 srtt = BPF_CORE_READ(tp, srtt_us) >> 3;
    if (srtt == 0)
        return 0;

    // Read destination address and port from sock_common
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    // dport is in network byte order, convert to host for display
    dport = __builtin_bswap16(dport);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct rtt_key key = { .daddr = daddr, .dport = dport };
    struct rtt_val *val = bpf_map_lookup_elem(&rtt_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->sum_us, (__u64)srtt);
        __sync_fetch_and_add(&val->count, 1);
        if (srtt < val->min_us || val->min_us == 0)
            val->min_us = srtt;
        if (srtt > val->max_us)
            val->max_us = srtt;
        val->last_pid = pid;
    } else {
        struct rtt_val new_val = {
            .sum_us = (__u64)srtt,
            .count = 1,
            .min_us = srtt,
            .max_us = srtt,
            .last_pid = pid,
        };
        bpf_map_update_elem(&rtt_accum, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
