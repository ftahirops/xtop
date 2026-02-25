// SPDX-License-Identifier: GPL-2.0
// sockio.c — per-PID per-connection TCP IO attribution
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct sockio_key {
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};

struct sockio_val {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 recv_wait_ns;
    __u32 recv_count;
    __u32 max_recv_ns;
};

struct recv_start {
    __u64 ts;
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sockio_key);
    __type(value, struct sockio_val);
} sockio_accum SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct recv_start);
} recv_inflight SEC(".maps");

static __always_inline void add_tx(struct sock *sk, __u64 size)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return;

    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    struct sockio_key key = { .pid = pid, .daddr = daddr, .dport = dport };
    struct sockio_val *val = bpf_map_lookup_elem(&sockio_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->tx_bytes, size);
    } else {
        struct sockio_val new_val = { .tx_bytes = size };
        bpf_map_update_elem(&sockio_accum, &key, &new_val, BPF_NOEXIST);
    }
}

static __always_inline void add_rx(struct sock *sk, __u64 size)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return;

    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    struct sockio_key key = { .pid = pid, .daddr = daddr, .dport = dport };
    struct sockio_val *val = bpf_map_lookup_elem(&sockio_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->rx_bytes, size);
    } else {
        struct sockio_val new_val = { .rx_bytes = size };
        bpf_map_update_elem(&sockio_accum, &key, &new_val, BPF_NOEXIST);
    }
}

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    add_tx(sk, (__u64)size);
    return 0;
}

// tcp_cleanup_rbuf(struct sock *sk, int copied)
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
    if (copied <= 0)
        return 0;
    add_rx(sk, (__u64)copied);
    return 0;
}

// tcp_recvmsg kprobe: save timestamp + dest info
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg_enter, struct sock *sk)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    struct recv_start rs = {
        .ts = bpf_ktime_get_ns(),
        .daddr = daddr,
        .dport = dport,
    };
    bpf_map_update_elem(&recv_inflight, &pid, &rs, BPF_ANY);
    return 0;
}

// tcp_recvmsg kretprobe: compute wait time
SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(handle_tcp_recvmsg_exit)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct recv_start *rs = bpf_map_lookup_elem(&recv_inflight, &pid);
    if (!rs)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - rs->ts;
    __u32 daddr = rs->daddr;
    __u16 dport = rs->dport;
    bpf_map_delete_elem(&recv_inflight, &pid);

    // Skip stale entries > 30s
    if (delta > 30000000000ULL)
        return 0;

    struct sockio_key key = { .pid = pid, .daddr = daddr, .dport = dport };
    struct sockio_val *val = bpf_map_lookup_elem(&sockio_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->recv_wait_ns, delta);
        __sync_fetch_and_add(&val->recv_count, 1);
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        if (delta32 > val->max_recv_ns)
            val->max_recv_ns = delta32;
    } else {
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        struct sockio_val new_val = {
            .recv_wait_ns = delta,
            .recv_count = 1,
            .max_recv_ns = delta32,
        };
        bpf_map_update_elem(&sockio_accum, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
