// SPDX-License-Identifier: GPL-2.0
// kfreeskb.c — trace packet drops by reason code (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct drop_val {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct drop_val);
} drop_accum SEC(".maps");

// tracepoint/skb/kfree_skb format:
//   void *skbaddr, void *location, unsigned short protocol,
//   enum skb_drop_reason reason
struct kfree_skb_args {
    unsigned long long unused;
    const void *skbaddr;
    const void *location;
    unsigned short protocol;
    unsigned short pad;
    unsigned int reason;
};

SEC("tracepoint/skb/kfree_skb")
int handle_kfree_skb(struct kfree_skb_args *ctx)
{
    __u32 reason = ctx->reason;

    // Skip NOT_SPECIFIED (0) — too noisy, no diagnostic value
    if (reason == 0)
        return 0;

    struct drop_val *val = bpf_map_lookup_elem(&drop_accum, &reason);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct drop_val new_val = { .count = 1 };
        bpf_map_update_elem(&drop_accum, &reason, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
