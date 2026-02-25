// SPDX-License-Identifier: GPL-2.0
// sockstate.c — trace all TCP state transitions (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct state_key {
    __u16 oldstate;
    __u16 newstate;
};

struct state_val {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct state_key);
    __type(value, struct state_val);
} state_accum SEC(".maps");

// tracepoint/sock/inet_sock_set_state format (same as tcpconnlat)
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
int handle_sock_set_state(struct inet_sock_set_state_args *ctx)
{
    struct state_key key = {
        .oldstate = (__u16)ctx->oldstate,
        .newstate = (__u16)ctx->newstate,
    };

    struct state_val *val = bpf_map_lookup_elem(&state_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct state_val new_val = { .count = 1 };
        bpf_map_update_elem(&state_accum, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
