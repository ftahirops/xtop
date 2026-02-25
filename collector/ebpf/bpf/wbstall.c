// SPDX-License-Identifier: GPL-2.0
// wbstall.c — trace writeback wait events per PID (watchdog)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct wb_val {
    __u64 count;
    __u64 total_pages;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct wb_val);
} wb_accum SEC(".maps");

// tracepoint/writeback/writeback_wait format:
//   char name[32], unsigned long nr_pages, dev_t sb_dev, int reason
struct writeback_wait_args {
    unsigned long long unused;
    char name[32];
    unsigned long nr_pages;
    unsigned int sb_dev;
    int reason;
};

SEC("tracepoint/writeback/writeback_wait")
int handle_writeback_wait(struct writeback_wait_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 nr_pages = ctx->nr_pages;

    struct wb_val *val = bpf_map_lookup_elem(&wb_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        __sync_fetch_and_add(&val->total_pages, nr_pages);
    } else {
        struct wb_val new_val = { .count = 1, .total_pages = nr_pages };
        bpf_map_update_elem(&wb_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
