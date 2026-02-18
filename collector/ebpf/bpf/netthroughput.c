// SPDX-License-Identifier: GPL-2.0
// netthroughput.c — trace per-PID TCP send/receive bytes
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct net_val {
    __u64 tx_bytes;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct net_val);
} net_accum SEC(".maps");

static __always_inline void add_bytes(__u32 pid, __u64 tx, __u64 rx)
{
    struct net_val *val = bpf_map_lookup_elem(&net_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->tx_bytes, tx);
        __sync_fetch_and_add(&val->rx_bytes, rx);
    } else {
        struct net_val new_val = { .tx_bytes = tx, .rx_bytes = rx };
        bpf_map_update_elem(&net_accum, &pid, &new_val, BPF_NOEXIST);
    }
}

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;
    add_bytes(pid, (__u64)size, 0);
    return 0;
}

// tcp_cleanup_rbuf(struct sock *sk, int copied)
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || copied <= 0)
        return 0;
    add_bytes(pid, 0, (__u64)copied);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
