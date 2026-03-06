// SPDX-License-Identifier: GPL-2.0
// portscan.c — port scan detection: count RSTs per source IP and track port diversity (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct scan_val {
    __u64 rst_count;
    __u64 port_bitmap;  // 64-bit bitmap for port diversity (dport % 64)
    __u64 first_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, struct scan_val);
} scan_accum SEC(".maps");

// tcp_v4_send_reset(const struct sock *sk, struct sk_buff *skb)
// Fires when kernel sends RST = connection refused (port not listening).
// sk may be NULL or a listener — read the scanner's IP from the SKB.
SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(handle_tcp_v4_send_reset, struct sock *sk, struct sk_buff *skb)
{
    // Read source IP from SKB's IP header (the scanner's IP)
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 nh_off = BPF_CORE_READ(skb, network_header);
    struct iphdr *iph = (struct iphdr *)(head + nh_off);
    __u32 src_ip = BPF_CORE_READ(iph, saddr);
    if (src_ip == 0)
        return 0;

    // Read destination port from the TCP header in the SKB
    __u16 th_off = BPF_CORE_READ(skb, transport_header);
    struct tcphdr *th = (struct tcphdr *)(head + th_off);
    __u16 dport = __builtin_bswap16(BPF_CORE_READ(th, dest));
    __u64 bit = 1ULL << (dport % 64);

    struct scan_val *val = bpf_map_lookup_elem(&scan_accum, &src_ip);
    if (val) {
        __sync_fetch_and_add(&val->rst_count, 1);
        __sync_fetch_and_or(&val->port_bitmap, bit);
    } else {
        struct scan_val new_val = {
            .rst_count = 1,
            .port_bitmap = bit,
            .first_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&scan_accum, &src_ip, &new_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
