// SPDX-License-Identifier: GPL-2.0
// tcpconnlat.c — trace TCP connection establishment latency
//
// tcp_v4_connect records the start time, and the inet_sock_set_state
// tracepoint fires when the socket transitions to ESTABLISHED.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TCP_SYN_SENT  2
#define TCP_ESTABLISHED 1

struct conn_start {
    __u64 ts;
    __u32 pid;
};

struct connlat_val {
    __u64 total_ns;
    __u32 count;
    __u32 max_ns;
    __u32 last_pid;
    __u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);  // sock pointer as key
    __type(value, struct conn_start);
} conn_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  // PID as key
    __type(value, struct connlat_val);
} connlat_accum SEC(".maps");

// tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect, struct sock *sk)
{
    __u64 ts = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct conn_start start = { .ts = ts, .pid = pid };
    __u64 sk_key = (__u64)sk;
    bpf_map_update_elem(&conn_inflight, &sk_key, &start, BPF_ANY);
    return 0;
}

// tracepoint/sock/inet_sock_set_state provides:
//   const void *skaddr, int oldstate, int newstate,
//   __u16 sport, __u16 dport, __u16 family,
//   __u8 saddr[4], __u8 daddr[4], __u8 saddr_v6[16], __u8 daddr_v6[16]
struct inet_sock_set_state_args {
    unsigned long long unused;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct inet_sock_set_state_args *ctx)
{
    // Only care about SYN_SENT -> ESTABLISHED transitions
    if (ctx->oldstate != TCP_SYN_SENT || ctx->newstate != TCP_ESTABLISHED)
        return 0;

    __u64 sk_key = (__u64)ctx->skaddr;
    struct conn_start *start = bpf_map_lookup_elem(&conn_inflight, &sk_key);
    if (!start)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta = now - start->ts;
    __u32 pid = start->pid;

    // Read daddr
    __u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), ctx->daddr);

    bpf_map_delete_elem(&conn_inflight, &sk_key);

    // Accumulate per PID
    struct connlat_val *val = bpf_map_lookup_elem(&connlat_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->total_ns, delta);
        __sync_fetch_and_add(&val->count, 1);
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        if (delta32 > val->max_ns)
            val->max_ns = delta32;
        val->last_pid = pid;
        val->daddr = daddr;
    } else {
        __u32 delta32 = delta > 0xFFFFFFFF ? 0xFFFFFFFF : (__u32)delta;
        struct connlat_val new_val = {
            .total_ns = delta,
            .count = 1,
            .max_ns = delta32,
            .last_pid = pid,
            .daddr = daddr,
        };
        bpf_map_update_elem(&connlat_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
