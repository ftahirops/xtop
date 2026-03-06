// SPDX-License-Identifier: GPL-2.0
// dnsmon.c — DNS query monitor: track outbound DNS queries and inbound responses per PID (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define DNS_PORT 53

struct dns_val {
    __u64 query_count;
    __u64 total_query_bytes;
    __u64 total_resp_bytes;
    __u32 max_query_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct dns_val);
} dns_accum SEC(".maps");

// udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
// Outbound DNS queries: filter by dest port 53.
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    // Check if destination port is DNS (53)
    __u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 dport = __builtin_bswap16(dport_be);
    if (dport != DNS_PORT)
        return 0;

    struct dns_val *val = bpf_map_lookup_elem(&dns_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->query_count, 1);
        __sync_fetch_and_add(&val->total_query_bytes, (__u64)len);
        __u32 len32 = (__u32)len;
        if (len32 > val->max_query_len)
            val->max_query_len = len32;
    } else {
        struct dns_val new_val = {
            .query_count = 1,
            .total_query_bytes = (__u64)len,
            .total_resp_bytes = 0,
            .max_query_len = (__u32)len,
        };
        bpf_map_update_elem(&dns_accum, &pid, &new_val, BPF_ANY);
    }

    return 0;
}

// udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, ...)
// Inbound DNS responses: filter by source port 53 (which is skc_dport for the socket).
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    // For a connected UDP socket receiving from DNS, skc_dport is the remote port (53)
    __u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 dport = __builtin_bswap16(dport_be);
    if (dport != DNS_PORT)
        return 0;

    struct dns_val *val = bpf_map_lookup_elem(&dns_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->total_resp_bytes, (__u64)len);
    } else {
        struct dns_val new_val = {
            .query_count = 0,
            .total_query_bytes = 0,
            .total_resp_bytes = (__u64)len,
            .max_query_len = 0,
        };
        bpf_map_update_elem(&dns_accum, &pid, &new_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
