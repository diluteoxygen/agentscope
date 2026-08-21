/*
 * AgentScope eBPF Kernel Tracepoint Probe
 * Low-overhead kernel-level authority observation for Linux.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event_t {
    __u32 pid;
    __u32 event_type; /* 1=OPEN, 2=EXEC, 3=CONNECT */
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.event_type = 1;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.event_type = 2;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
