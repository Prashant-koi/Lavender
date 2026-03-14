#ifdef __INTELLISENSE__
#define BPF_NO_PRESERVE_ACCESS_INDEX
#endif
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
 * Event sent to user space through ring buffer.
 * We need to keep struct in sync with the Rust-side event layout.
 */
struct exec_event {
    u32 pid;
    u32 ppid;
    u8  comm[16];    // process name, kernel limits this to 16 bytes (TASK_COMM_LEN)
    u8  filename[256];
};

/*
 * Ring buffer map used to stream events to user space.
 * max_entries is total buffer capacity in bytes.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Tracepoint program: runs every time sys_enter_execve fires.
 * We collect process metadata and the target filename and publish it.
 */
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;  // buffer full, drop this event

    // the uppper 32 bits is pid and the lower 32 is tgid(thread group ID) that the bpf_get_current_task() returns
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    // we will read the parent pid usinf CO-RE so that ensures that it is portable
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // command name (comm)
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // args[0] for execve is const char *filename in user memory.
    const char *filename_ptr = (const char *)ctx->args[0];

    // we will copy the user space string into fixed buffer
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0); // submit to user space, the event

    return 0;
}

// we need this or else the verification part might fail
char LICENSE[] SEC("license") = "GPL";