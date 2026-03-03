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

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

#define TC_ACT_OK 0

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __u16         h_proto;
} __attribute__((packed));

struct iphdr {
    __u8  ihl_ver;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 flags_offset; // data offset + reserved + flags
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

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

// Check if the flag combination is anomalous:
//   XMAS scan:       FIN+PSH+URG (0x29)
//   NULL scan:       no flags set (0x00)
//   SYN+FIN:         illegal combination (0x03)
//   FIN without ACK: RFC violation
static __always_inline int is_anomalous(__u8 flags)
{
    // XMAS: FIN+PUSH+URG
    if ((flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG))
        return 1;
    // NULL: no flags at all
    if (flags == 0x00)
        return 1;
    // SYN+FIN: illegal
    if ((flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN))
        return 1;
    // FIN without ACK: RFC violation
    if ((flags & TH_FIN) && !(flags & TH_ACK))
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

    // Compute IP header length (IHL is lower nibble, in 4-byte units)
    __u8 ihl = (ip->ihl_ver & 0x0F) * 4;
    if (ihl < 20)
        return TC_ACT_OK;

    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Extract flags: lower 8 bits of flags_offset (network byte order)
    // TCP flags are in the second byte of the 2-byte field after data offset
    __u8 flags = (__u8)(__builtin_bswap16(tcp->flags_offset) & 0x3F);

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
        bpf_map_update_elem(&flags_accum, &key, &new_val, BPF_NOEXIST);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
