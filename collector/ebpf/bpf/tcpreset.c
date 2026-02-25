// SPDX-License-Identifier: GPL-2.0
// tcpreset.c — trace TCP RST events per PID (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct reset_val {
    __u64 count;
    __u32 last_daddr;
    __u16 last_dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct reset_val);
} reset_accum SEC(".maps");

// tcp_send_reset(const struct sock *sk, struct sk_buff *skb)
SEC("kprobe/tcp_send_reset")
int BPF_KPROBE(handle_tcp_send_reset, struct sock *sk)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    struct reset_val *val = bpf_map_lookup_elem(&reset_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->last_daddr = daddr;
        val->last_dport = dport;
    } else {
        struct reset_val new_val = {
            .count = 1,
            .last_daddr = daddr,
            .last_dport = dport,
        };
        bpf_map_update_elem(&reset_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
