// SPDX-License-Identifier: GPL-2.0
// synflood.c — SYN flood detection: count SYN requests and SYN-ACK retransmits per source IP (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct syn_val {
    __u64 syn_count;
    __u64 synack_retrans;
    __u64 first_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct syn_val);
} syn_accum SEC(".maps");

// tcp_conn_request(struct request_sock_ops *rsk_ops,
//                  const struct tcp_request_sock_ops *af_ops,
//                  struct sock *sk, struct sk_buff *skb)
// sk is the LISTENING socket — skc_daddr is 0 or local, NOT the attacker.
// Read the source IP from the SKB's IP header instead.
SEC("kprobe/tcp_conn_request")
int BPF_KPROBE(handle_tcp_conn_request, void *rsk_ops, void *af_ops, struct sock *sk, struct sk_buff *skb)
{
    // Read source IP from the SKB's IP header (the actual SYN sender)
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 nh_off = BPF_CORE_READ(skb, network_header);
    struct iphdr *iph = (struct iphdr *)(head + nh_off);
    __u32 src_ip = BPF_CORE_READ(iph, saddr);
    if (src_ip == 0)
        return 0;

    struct syn_val *val = bpf_map_lookup_elem(&syn_accum, &src_ip);
    if (val) {
        __sync_fetch_and_add(&val->syn_count, 1);
    } else {
        struct syn_val new_val = {
            .syn_count = 1,
            .synack_retrans = 0,
            .first_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&syn_accum, &src_ip, &new_val, BPF_ANY);
    }

    return 0;
}

// tcp_retransmit_synack(const struct sock *sk, const struct request_sock *req)
// Called when the kernel retransmits a SYN-ACK (client didn't ACK).
// req->__req_common.skc_daddr holds the remote (SYN source) IP.
SEC("kprobe/tcp_retransmit_synack")
int BPF_KPROBE(handle_tcp_retransmit_synack, struct sock *sk, struct request_sock *req)
{
    __u32 src_ip = BPF_CORE_READ(req, __req_common.skc_daddr);
    if (src_ip == 0)
        return 0;

    struct syn_val *val = bpf_map_lookup_elem(&syn_accum, &src_ip);
    if (val) {
        __sync_fetch_and_add(&val->synack_retrans, 1);
    } else {
        struct syn_val new_val = {
            .syn_count = 0,
            .synack_retrans = 1,
            .first_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&syn_accum, &src_ip, &new_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
