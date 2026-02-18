// SPDX-License-Identifier: GPL-2.0
// iolatency.c — trace block IO latency per PID via tracepoints
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define HIST_SLOTS 16

struct rq_key {
    __u32 dev;
    __u64 sector;
};

struct rq_start {
    __u32 pid;
    __u64 start_ns;
};

struct iolat_val {
    __u64 total_ns;
    __u64 max_ns;
    __u32 count;
    __u32 slots[HIST_SLOTS];
    __u32 dev;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct rq_key);
    __type(value, struct rq_start);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct iolat_val);
} iolat_hist SEC(".maps");

// Tracepoint format for block_rq_issue and block_rq_complete
struct block_rq_args {
    unsigned long long unused;
    __u32 dev;
    char pad1[4];      // alignment
    __u64 sector;
    __u32 nr_sector;
    __u32 bytes;
    char rwbs[8];
    char comm[16];
};

static __always_inline __u32 log2_slot(__u64 us)
{
    __u32 slot = 0;
    __u64 v = us;
    #pragma unroll
    for (int i = 0; i < HIST_SLOTS - 1; i++) {
        if (v > 1) {
            v >>= 1;
            slot++;
        }
    }
    if (slot >= HIST_SLOTS)
        slot = HIST_SLOTS - 1;
    return slot;
}

SEC("tracepoint/block/block_rq_issue")
int handle_block_rq_issue(struct block_rq_args *ctx)
{
    __u32 dev = ctx->dev;
    __u64 sector = ctx->sector;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct rq_key key = { .dev = dev, .sector = sector };
    struct rq_start val = { .pid = pid, .start_ns = bpf_ktime_get_ns() };

    bpf_map_update_elem(&inflight, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int handle_block_rq_complete(struct block_rq_args *ctx)
{
    __u32 dev = ctx->dev;
    __u64 sector = ctx->sector;

    struct rq_key key = { .dev = dev, .sector = sector };
    struct rq_start *start = bpf_map_lookup_elem(&inflight, &key);
    if (!start)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - start->start_ns;
    __u32 pid = start->pid;
    bpf_map_delete_elem(&inflight, &key);

    if (delta == 0 || pid == 0)
        return 0;

    __u64 us = delta / 1000;
    __u32 slot = log2_slot(us);

    struct iolat_val *val = bpf_map_lookup_elem(&iolat_hist, &pid);
    if (val) {
        __sync_fetch_and_add(&val->total_ns, delta);
        __sync_fetch_and_add(&val->count, 1);
        __sync_fetch_and_add(&val->slots[slot & (HIST_SLOTS - 1)], 1);
        if (delta > val->max_ns)
            val->max_ns = delta;
    } else {
        struct iolat_val new_val = {};
        new_val.total_ns = delta;
        new_val.max_ns = delta;
        new_val.count = 1;
        new_val.dev = dev;
        new_val.slots[slot & (HIST_SLOTS - 1)] = 1;
        bpf_map_update_elem(&iolat_hist, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
