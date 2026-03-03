// SPDX-License-Identifier: GPL-2.0
// connrate.c — connection rate tracker: monitor connect/close rates per PID+dest (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET     2
#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_FIN_WAIT1   4
#define TCP_CLOSE_WAIT  8

struct flow_key {
    __u32 pid;
    __u32 daddr;
};

struct flow_val {
    __u64 connect_count;
    __u64 close_count;
    __u64 first_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flow_accum SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} dest_count SEC(".maps");

// tracepoint/sock/inet_sock_set_state format (same as sockstate.c / tcpconnlat.c)
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
int handle_connrate(struct inet_sock_set_state_args *ctx)
{
    // IPv4 + TCP only
    if (ctx->family != AF_INET)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;

    // Detect connect: SYN_SENT -> ESTABLISHED
    int is_connect = (oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED);
    // Detect close: ESTABLISHED -> CLOSE_WAIT or ESTABLISHED -> FIN_WAIT1
    int is_close = (oldstate == TCP_ESTABLISHED &&
                    (newstate == TCP_CLOSE_WAIT || newstate == TCP_FIN_WAIT1));

    if (!is_connect && !is_close)
        return 0;

    // Read destination address
    __u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), ctx->daddr);

    struct flow_key key = { .pid = pid, .daddr = daddr };

    struct flow_val *val = bpf_map_lookup_elem(&flow_accum, &key);
    if (val) {
        if (is_connect)
            __sync_fetch_and_add(&val->connect_count, 1);
        if (is_close)
            __sync_fetch_and_add(&val->close_count, 1);
    } else {
        struct flow_val new_val = {
            .connect_count = is_connect ? 1 : 0,
            .close_count = is_close ? 1 : 0,
            .first_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_accum, &key, &new_val, BPF_NOEXIST);
    }

    // Track unique destination count per PID (on connect only)
    if (is_connect) {
        __u64 *cnt = bpf_map_lookup_elem(&dest_count, &pid);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        } else {
            __u64 one = 1;
            bpf_map_update_elem(&dest_count, &pid, &one, BPF_NOEXIST);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
