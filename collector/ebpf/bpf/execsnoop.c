// SPDX-License-Identifier: GPL-2.0
// execsnoop.c — trace process executions via sched_process_exec (sentinel)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct exec_val {
    __u64 count;
    __u64 ts;
    __u32 ppid;
    __u32 uid;
    char  comm[16];
    char  filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct exec_val);
} exec_accum SEC(".maps");

// Helper: read the __data_loc filename from tracepoint context.
// __data_loc is a u32 at offset 8: lower 16 bits = offset, upper 16 = length.
static __always_inline void read_filename(void *ctx, char *buf, __u32 buf_sz)
{
    __u32 data_loc = 0;
    bpf_probe_read_kernel(&data_loc, sizeof(data_loc), ctx + 8);
    __u16 off = data_loc & 0xFFFF;
    bpf_probe_read_kernel_str(buf, buf_sz, ctx + off);
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Get PPID from current->real_parent->tgid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = 0;
    BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);

    struct exec_val *val = bpf_map_lookup_elem(&exec_accum, &pid);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->ts = bpf_ktime_get_ns();
        val->ppid = ppid;
        val->uid = uid;
        bpf_get_current_comm(&val->comm, sizeof(val->comm));
        read_filename(ctx, val->filename, sizeof(val->filename));
    } else {
        struct exec_val new_val = {};
        new_val.count = 1;
        new_val.ts = bpf_ktime_get_ns();
        new_val.ppid = ppid;
        new_val.uid = uid;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        read_filename(ctx, new_val.filename, sizeof(new_val.filename));

        bpf_map_update_elem(&exec_accum, &pid, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
