// SPDX-License-Identifier: GPL-2.0
// modload.c — trace kernel module loading events (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct mod_val {
    __u64 count;
    __u64 ts;
    char name[56];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct mod_val);
} mod_accum SEC(".maps");

// do_init_module(struct module *mod)
SEC("kprobe/do_init_module")
int BPF_KPROBE(handle_do_init_module, struct module *mod)
{
    char name[56] = {};
    BPF_CORE_READ_STR_INTO(&name, mod, name);

    // Use first 8 bytes of name as key
    __u64 key = 0;
    __builtin_memcpy(&key, name, 8);

    struct mod_val *val = bpf_map_lookup_elem(&mod_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->ts = bpf_ktime_get_ns();
    } else {
        struct mod_val new_val = { .count = 1, .ts = bpf_ktime_get_ns() };
        __builtin_memcpy(new_val.name, name, 56);
        bpf_map_update_elem(&mod_accum, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
