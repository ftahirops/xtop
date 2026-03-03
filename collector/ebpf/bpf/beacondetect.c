// SPDX-License-Identifier: GPL-2.0
// beacondetect.c — C2 beacon interval detection (watchdog)
//
// kprobe on tcp_sendmsg that tracks inter-packet timing per
// (PID, destination IP, destination port). Regular beacon intervals
// are a strong indicator of C2 communication.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Interval bounds: only track intervals between 100ms and 600s
#define MIN_INTERVAL_NS 100000000ULL       // 100ms
#define MAX_INTERVAL_NS 600000000000ULL    // 600s

struct beacon_key {
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u16 pad;
};

struct beacon_val {
    __u64 last_ns;
    __u64 interval_sum_ns;
    __u64 interval_count;
    __u64 min_interval_ns;
    __u64 max_interval_ns;
    __u64 send_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct beacon_key);
    __type(value, struct beacon_val);
} beacon_accum SEC(".maps");

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_beacon_sendmsg, struct sock *sk)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    __u64 now = bpf_ktime_get_ns();

    struct beacon_key key = {
        .pid = pid,
        .daddr = daddr,
        .dport = dport,
    };

    struct beacon_val *val = bpf_map_lookup_elem(&beacon_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->send_count, 1);

        if (val->last_ns != 0) {
            __u64 interval = now - val->last_ns;

            // Only track reasonable intervals
            if (interval >= MIN_INTERVAL_NS && interval <= MAX_INTERVAL_NS) {
                __sync_fetch_and_add(&val->interval_sum_ns, interval);
                __sync_fetch_and_add(&val->interval_count, 1);

                if (interval < val->min_interval_ns || val->min_interval_ns == 0)
                    val->min_interval_ns = interval;
                if (interval > val->max_interval_ns)
                    val->max_interval_ns = interval;
            }
        }

        val->last_ns = now;
    } else {
        struct beacon_val new_val = {
            .last_ns = now,
            .interval_sum_ns = 0,
            .interval_count = 0,
            .min_interval_ns = 0,
            .max_interval_ns = 0,
            .send_count = 1,
        };
        bpf_map_update_elem(&beacon_accum, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
