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
struct exec_event 
{
    u32 pid;
    u32 ppid;
    u32 uid;
    u8  comm[16];    // process name, kernel limits this to 16 bytes (TASK_COMM_LEN)
    u8  filename[256];
};

/*
    Contains the pid of processes that died
*/
struct exit_event
{
    u32 pid;
};

/*
 contains info on the event that are opened by a process
*/
struct open_event
{
    u32 pid;
    u8 comm[16];
    u8 filename[256]; // the file being opened
};

/*
    contains info about whever a process opens a network connection
*/
struct conn_event 
{
    u32 pid;
    u32 uid;
    u8 comm[16];
    u8 daddr[16]; // the destiantion ip is beig enough for IPv6, IPv4 uses the first 4 bytes
    u16 dport; // the destination port
    u16 af; // the address family (Ipv4 or IPv6) so rust agent knows hwo to interpret the IP
};

/*
 * Ring buffer map used to stream events to user space.
 * max_entries is total buffer capacity in bytes.
 */
struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

/*
    Ring buffer map used to stream events to user space
    This one contains the processes that died
*/
struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exit_events SEC(".maps");

/*
    This ring buffer contains the openevents one
*/
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} open_events SEC(".maps");


/*
    ring buffer about conn_events
*/
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} conn_events SEC(".maps");

/*
 * Tracepoint program: runs every time sys_enter_execve fires.
 * We collect process metadata and the target filename and publish it.
 */
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e) return 0;  // buffer full, drop this event

    // the uppper 32 bits is pid and the lower 32 is tgid(thread group ID) that the bpf_get_current_task() returns
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    // add the uid the lower 32 bits is uid upper 32 is gid
    u64 ugid =  bpf_get_current_uid_gid();
    e->uid = (u32)(ugid & 0xFFFFFFFF);

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

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    // reserve space in the exit ring buffer
    u32 *pid_slot = bpf_ringbuf_reserve(&exit_events, sizeof(u32), 0);
    if (!pid_slot) return 0;

    // upper 32 is the pid bottom is the tgid reference comments in handle_execve function
    u64 id = bpf_get_current_pid_tgid();
    *pid_slot = id >> 32;

    bpf_ringbuf_submit(pid_slot, 0);
    
    return 0;
}

/*
    Tracepoint for open events
*/
SEC("tp/syscalls/sys_enter_openat")
int handle_open(struct trace_event_raw_sys_enter *ctx)
{   
    //reserve space
    struct open_event *o = bpf_ringbuf_reserve(&open_events, sizeof(*o), 0);
    if (!o) return 0; 

    // the uppper 32 bits is pid and the lower 32 is tgid(thread group ID) that the bpf_get_current_task() returns
    u64 id = bpf_get_current_pid_tgid();
    o->pid = id >> 32;

    // command name (comm)
    bpf_get_current_comm(&o->comm, sizeof(o->comm));

    // args[0] for execve is const char *filename in user memory.
    const char *filename_ptr = (const char *)ctx->args[1];

    // we will copy the user space string into fixed buffer
    bpf_probe_read_user_str(o->filename, sizeof(o->filename), filename_ptr);

    bpf_ringbuf_submit(o, 0); // submit to user space, the event

    return 0;
}

/*
    Tracepoint for new netwrk connections
*/
SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct conn_event *e = bpf_ringbuf_reserve(&conn_events, sizeof(*e), 0);
    if (!e) return 0;

    // initialize fields in case a partial parse path is hit
    __builtin_memset(&e->daddr, 0, sizeof(e->daddr));
    e->dport = 0;

    //upper 32 bits is pid
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    // add the uid the lower 32 bits is uid upper 32 is gid
    u64 ugid =  bpf_get_current_uid_gid();
    e->uid = (u32)(ugid & 0xFFFFFFFF);

    //command name (comm)
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    // address familt read first, first 2 bytes of any sockaddr
    u16 af = 0;
    bpf_probe_read_user(&af, sizeof(af), &addr->sa_family);
    e->af = af;

    if (af==2) // AF_INET - IPv4
    {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), addr);

        // since sin_port is big-endian we swap bytes to get redable port number
        e->dport = __builtin_bswap16(sa.sin_port);

        //copy 4 bytes of IPv4 address into first 4 bytes of daddr
        __builtin_memcpy(&e->daddr, &sa.sin_addr, 4);
    } else if (af == 10) // AF-INET6 -IPv6
    {
        struct sockaddr_in6 sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), addr);

        e->dport = __builtin_bswap16(sa.sin6_port);
        __builtin_memcpy(&e->daddr, &sa.sin6_addr, 16);
    } else 
    {
        // mybe unix socker or something else 
        // we will discard the reserved slot instead of submitting garbage
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// we need this or else the verification part might fail
char LICENSE[] SEC("license") = "GPL";