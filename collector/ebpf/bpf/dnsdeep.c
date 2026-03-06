// SPDX-License-Identifier: GPL-2.0
// dnsdeep.c — deep DNS payload inspector (watchdog)
//
// TC ingress classifier that parses DNS query packets to detect
// anomalous patterns: excessive TXT queries (tunneling indicator),
// unusually long query names (exfiltration indicator).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETH_P_IP    0x0800
#define IPPROTO_UDP 17
#define DNS_PORT    53
#define DNS_TYPE_TXT 16
#define TC_ACT_OK   0

// DNS header: 12 bytes
struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));

struct dns_deep_val {
    __u64 total_queries;
    __u64 txt_queries;
    __u64 total_query_bytes;
    __u32 max_name_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct dns_deep_val);
} dns_deep SEC(".maps");

SEC("tc")
int handle_dnsdeep(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u8 ihl = ip->ihl * 4;
    if (ihl < 20)
        return TC_ACT_OK;
    if (ihl > 60)
        return TC_ACT_OK;

    // Parse UDP header — validate bounds before forming pointer
    if ((void *)ip + ihl + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;
    struct udphdr *udp = (void *)ip + ihl;

    // Filter DNS: destination port 53
    if (udp->dest != __builtin_bswap16(DNS_PORT))
        return TC_ACT_OK;

    // Parse DNS header
    struct dnshdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return TC_ACT_OK;

    // Only interested in queries (QR bit = 0 in flags, flags are network order)
    __u16 flags = __builtin_bswap16(dns->flags);
    if (flags & 0x8000) // QR bit set = response, skip
        return TC_ACT_OK;

    // Walk query name labels to compute total name length
    // DNS names are a sequence of length-prefixed labels ending with 0x00
    __u8 *qname = (__u8 *)(dns + 1);
    __u32 name_len = 0;
    __u8 label_len = 0;

    #pragma unroll
    for (int i = 0; i < 128; i++) {
        __u8 *pos = qname + name_len;
        if ((void *)(pos + 1) > data_end)
            break;

        label_len = *pos;

        // End of name
        if (label_len == 0)
            break;

        // Sanity: label can't exceed 63 bytes per RFC
        if (label_len > 63)
            break;

        // Advance past label length byte + label data
        name_len += 1 + label_len;
    }

    // Sanity: DNS names cannot exceed 253 bytes per RFC 1035
    if (name_len > 253)
        return TC_ACT_OK;

    // After the name, read QTYPE (2 bytes)
    __u8 *qtype_ptr = qname + name_len + 1; // +1 for the terminating 0x00
    if ((void *)(qtype_ptr + 2) > data_end)
        return TC_ACT_OK;

    __u16 qtype = 0;
    qtype = ((__u16)qtype_ptr[0] << 8) | (__u16)qtype_ptr[1];

    // Accumulate per source IP
    __u32 saddr = ip->saddr;
    struct dns_deep_val *val = bpf_map_lookup_elem(&dns_deep, &saddr);
    if (val) {
        __sync_fetch_and_add(&val->total_queries, 1);
        __sync_fetch_and_add(&val->total_query_bytes, (__u64)name_len);
        if (qtype == DNS_TYPE_TXT)
            __sync_fetch_and_add(&val->txt_queries, 1);
        if (name_len > val->max_name_len)
            val->max_name_len = name_len;
    } else {
        struct dns_deep_val new_val = {
            .total_queries = 1,
            .txt_queries = (qtype == DNS_TYPE_TXT) ? 1 : 0,
            .total_query_bytes = name_len,
            .max_name_len = name_len,
        };
        bpf_map_update_elem(&dns_deep, &saddr, &new_val, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
