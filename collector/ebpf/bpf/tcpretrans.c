// SPDX-License-Identifier: GPL-2.0
// tcpretrans.c — trace TCP retransmissions per PID
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct retrans_val {
    __u32 count;
    __u16 last_sport;
    __u16 last_dport;
    __u32 last_daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct retrans_val);
} retrans_accum SEC(".maps");

// tracepoint/tcp/tcp_retransmit_skb provides:
//   const void *skbaddr, const void *skaddr, int state,
//   __u16 sport, __u16 dport, __u16 family,
//   __u8 saddr[4], __u8 daddr[4], __u8 saddr_v6[16], __u8 daddr_v6[16]
struct tcp_retransmit_skb_args {
    unsigned long long unused;
    const void *skbaddr;
    const void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

SEC("tracepoint/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit(struct tcp_retransmit_skb_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    // pid=0 means kernel timer context; still record it

    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;
    __u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), ctx->daddr);

    struct retrans_val *val = bpf_map_lookup_elem(&retrans_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->last_sport = sport;
        val->last_dport = dport;
        val->last_daddr = daddr;
    } else {
        struct retrans_val new_val = {
            .count = 1,
            .last_sport = sport,
            .last_dport = dport,
            .last_daddr = daddr,
        };
        bpf_map_update_elem(&retrans_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
