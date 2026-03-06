// SPDX-License-Identifier: GPL-2.0
// tcpflags.c — detect anomalous TCP flag combinations (watchdog)
//
// TC ingress classifier that monitors for XMAS, NULL, SYN+FIN,
// and FIN-without-ACK packets — common scan/attack signatures.
// Monitoring only: always returns TC_ACT_OK (never drops).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

#define TC_ACT_OK 0

struct flags_key {
    __u32 saddr;
    __u8  flags;
    __u8  pad[3];
};

struct flags_val {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct flags_key);
    __type(value, struct flags_val);
} flags_accum SEC(".maps");

// Build a flags byte from the individual tcphdr bitfields.
static __always_inline __u8 extract_tcp_flags(struct tcphdr *tcp)
{
    __u8 f = 0;
    if (tcp->fin) f |= 0x01;
    if (tcp->syn) f |= 0x02;
    if (tcp->rst) f |= 0x04;
    if (tcp->psh) f |= 0x08;
    if (tcp->ack) f |= 0x10;
    if (tcp->urg) f |= 0x20;
    return f;
}

// Check if the flag combination is anomalous:
//   XMAS scan:       FIN+PSH+URG (0x29)
//   NULL scan:       no flags set (0x00)
//   SYN+FIN:         illegal combination (0x03)
//   FIN without ACK: RFC violation
static __always_inline int is_anomalous(__u8 flags)
{
    // XMAS: FIN+PUSH+URG
    if ((flags & 0x29) == 0x29)
        return 1;
    // NULL: no flags at all
    if (flags == 0x00)
        return 1;
    // SYN+FIN: illegal
    if ((flags & 0x03) == 0x03)
        return 1;
    // FIN without ACK: RFC violation
    if ((flags & 0x01) && !(flags & 0x10))
        return 1;
    return 0;
}

SEC("tc")
int handle_tcpflags(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only IPv4
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Only TCP
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // Compute IP header length (IHL is in 4-byte units)
    __u8 ihl = ip->ihl * 4;
    if (ihl < 20)
        return TC_ACT_OK;
    if (ihl > 60)
        return TC_ACT_OK;

    // Parse TCP header — validate bounds before forming pointer
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;
    struct tcphdr *tcp = (void *)ip + ihl;

    // Extract flags from individual bitfields
    __u8 flags = extract_tcp_flags(tcp);

    if (!is_anomalous(flags))
        return TC_ACT_OK;

    struct flags_key key = {
        .saddr = ip->saddr,
        .flags = flags,
    };

    struct flags_val *val = bpf_map_lookup_elem(&flags_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct flags_val new_val = { .count = 1 };
        bpf_map_update_elem(&flags_accum, &key, &new_val, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
