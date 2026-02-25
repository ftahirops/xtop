// SPDX-License-Identifier: GPL-2.0
// ptracedetect.c — trace ptrace syscalls for injection detection (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define PTRACE_POKETEXT   4
#define PTRACE_POKEDATA   5
#define PTRACE_SETREGS    13
#define PTRACE_ATTACH     16
#define PTRACE_SEIZE      0x4206

// Composite key: tracks each (tracer, target) pair separately
struct ptrace_key {
    __u32 tracer_pid;
    __u32 target_pid;
};

struct ptrace_val {
    __u64 count;
    __u64 ts;
    __u64 request;
    char  tracer_comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct ptrace_key);
    __type(value, struct ptrace_val);
} ptrace_accum SEC(".maps");

// tracepoint/syscalls/sys_enter_ptrace args:
//   int __syscall_nr, long request, long pid, long addr, long data
struct sys_enter_ptrace_args {
    unsigned long long unused;
    long syscall_nr;
    long request;
    long pid;
    long addr;
    long data;
};

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_sys_enter_ptrace(struct sys_enter_ptrace_args *ctx)
{
    __u64 req = (__u64)ctx->request;

    // Only track suspicious ptrace operations
    if (req != PTRACE_ATTACH && req != PTRACE_SEIZE &&
        req != PTRACE_POKETEXT && req != PTRACE_POKEDATA &&
        req != PTRACE_SETREGS)
        return 0;

    __u32 tracer_pid = bpf_get_current_pid_tgid() >> 32;
    if (tracer_pid == 0)
        return 0;

    __u32 target_pid = (__u32)ctx->pid;

    struct ptrace_key key = {
        .tracer_pid = tracer_pid,
        .target_pid = target_pid,
    };

    struct ptrace_val *val = bpf_map_lookup_elem(&ptrace_accum, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->ts = bpf_ktime_get_ns();
        val->request = req;
        bpf_get_current_comm(&val->tracer_comm, sizeof(val->tracer_comm));
    } else {
        struct ptrace_val new_val = {
            .count = 1,
            .ts = bpf_ktime_get_ns(),
            .request = req,
        };
        bpf_get_current_comm(&new_val.tracer_comm, sizeof(new_val.tracer_comm));
        bpf_map_update_elem(&ptrace_accum, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
