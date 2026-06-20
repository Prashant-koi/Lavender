use async_nats::rustls::crypto::hash::Hash;
use aya::maps::{MapData, RingBuf, HashMap};
use aya::programs::{ self, Lsm, TracePoint };
use aya::{include_bytes_aligned, Btf, Bpf};
use tokio::io::unix::AsyncFd;

pub struct AgentBootstrap {
    // keep bpf alive so attached programs/maps stay valid for runtime
    pub _bpf: Bpf,
    pub exec_fd: AsyncFd<RingBuf<MapData>>,
    pub exit_fd: AsyncFd<RingBuf<MapData>>,
    pub open_fd: AsyncFd<RingBuf<MapData>>,
    pub conn_fd: AsyncFd<RingBuf<MapData>>,
}

fn attach_tracepoint(
    bpf: &mut Bpf,
    program_name: &str,
    category: &str,
    tracepoint_name: &str,
) {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .unwrap()
        .try_into()
        .unwrap();

    program.load().unwrap();
    program.attach(category, tracepoint_name).unwrap();
}

fn take_ringbuf_fd(bpf: &mut Bpf, map_name: &str) -> AsyncFd<RingBuf<MapData>> {
    let ring = RingBuf::try_from(bpf.take_map(map_name).unwrap()).unwrap();
    AsyncFd::new(ring).unwrap()
}

fn attach_kill_protection(bpf: &mut Bpf) {
    // lsm programs resolve ther hooks agains the running kernels BTF so we need to load
    // the kernel type info first
    let btf = Btf::from_sys_fs().unwrap();

    let program: &mut Lsm = bpf 
        .program_mut("task_kill")
        .unwrap()
        .try_into()
        .unwrap();

    // first arg is kernel hook name
    program.load("task_kill", &btf).unwrap();
    program.attach().unwrap();

    // protect pid
    let mut protected: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("PROTECTED_PID").unwrap()).unwrap();
    protected.insert(std::process::id(), 1u8, 0).unwrap();
}

pub fn bootstrap_bpf() -> AgentBootstrap {
    // We will Load the compiled eBPF object file.
    // This contains the kernel-side program and maps.
    let bytecode = include_bytes_aligned!(env!("LAVENDER_EBPF_PATH"));
    let mut bpf = Bpf::load(bytecode).unwrap();

    attach_tracepoint(&mut bpf, "handle_execve", "syscalls", "sys_enter_execve");
    attach_tracepoint(&mut bpf, "handle_exit", "sched", "sched_process_exit");
    attach_tracepoint(&mut bpf, "handle_open", "syscalls", "sys_enter_openat");
    attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect");

    attach_kill_protection(&mut bpf);

    let exec_fd = take_ringbuf_fd(&mut bpf, "EXEC_EVENTS");
    let exit_fd = take_ringbuf_fd(&mut bpf, "EXIT_EVENTS");
    let open_fd = take_ringbuf_fd(&mut bpf, "OPEN_EVENTS");
    let conn_fd = take_ringbuf_fd(&mut bpf, "CONN_EVENTS");

    AgentBootstrap {
        _bpf: bpf,
        exec_fd,
        exit_fd,
        open_fd,
        conn_fd,
    }
}