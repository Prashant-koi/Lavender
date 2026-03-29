use aya::{Bpf, include_bytes_aligned};
use aya::programs::TracePoint;
use aya::maps::RingBuf;
use common::{ExecEvent, OpenEvent, ConnEvent};
use agent::config;
use agent::conn_handler;
use agent::correlator::Correlator;
use agent::exec_handler;
use agent::exit_handler;
use agent::open_handler;
use agent::response::ResponseEngine;
use agent::runtime::ProcessNode;
use agent::scorer::Scorer;
use agent::users;
use std::collections::{HashMap, HashSet};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() {
    // we will load the config first
    let config = config::Config::load_auto();
    let user_db = users::UserDb::load();

    // We will Load the compiled eBPF object file.
    // This contains the kernel-side program and maps.
    let bytecode = include_bytes_aligned!(env!("LAVENDER_EBPF_PATH"));
    let mut bpf  = Bpf::load(bytecode).unwrap();

    // Grab the tracepoint program by name and cast it to TracePoint
    // THis way we can load and attach it
    let execve_program: &mut TracePoint = bpf
        .program_mut("handle_execve")
        .unwrap()
        .try_into()
        .unwrap();
    
    // We will load program into the kernel and attach it to execve tracepoint.
    execve_program.load().unwrap();
    execve_program.attach("syscalls", "sys_enter_execve").unwrap();

     // we will do handle_exit the same way as handle_execve
    let exit_program: &mut TracePoint = bpf
        .program_mut("handle_exit")
        .unwrap()
        .try_into()
        .unwrap();

    exit_program.load().unwrap();
    exit_program.attach("sched", "sched_process_exit").unwrap();

    let open_program: &mut TracePoint = bpf
        .program_mut("handle_open")
        .unwrap()
        .try_into()
        .unwrap();

    open_program.load().unwrap();
    open_program.attach("syscalls", "sys_enter_openat").unwrap();

    // the network connection one
    let conn_program: &mut TracePoint = bpf
        .program_mut("handle_connect")
        .unwrap()
        .try_into()
        .unwrap();

    conn_program.load().unwrap();
    conn_program.attach("syscalls", "sys_enter_connect").unwrap();

    // Get a handle to the ring buffer map used to send events
    // from eBPF (from the kernel space) to this user-space process
    let execve_ring = RingBuf::try_from(bpf.take_map("EXEC_EVENTS").unwrap()).unwrap();
    // Wrap ring buffer in AsyncFd so tokio can await readiness
    // without blocking the async runtime.
    let mut ring_fd = AsyncFd::new(execve_ring).unwrap();
    
    let exit_ring = RingBuf::try_from(bpf.take_map("EXIT_EVENTS").unwrap()).unwrap();
    let mut exit_fd = AsyncFd::new(exit_ring).unwrap();

    let open_ring = RingBuf::try_from(bpf.take_map("OPEN_EVENTS").unwrap()).unwrap();
    let mut open_fd = AsyncFd::new(open_ring).unwrap();

    let conn_ring = RingBuf::try_from(bpf.take_map("CONN_EVENTS").unwrap()).unwrap();
    let mut conn_fd = AsyncFd::new(conn_ring).unwrap();

    let mut process_tree: HashMap<u32, ProcessNode> = HashMap::new();
    let mut seen_network_callers: HashSet<String> = HashSet::new(); // a hashset to just store seen network callers for check
    let mut correlator = Correlator::from_filters(&config.filters);
    let mut scorer = Scorer::new();
    let response_engine = ResponseEngine::from_config(&config.response);


    println!("Lavender is watching. Ctrl+C to stop");

    loop {
        tokio::select! {
            //arm 1
            // We will wait until the ring buffer has data.
            Ok(mut guard) = ring_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                // We will drain all currently available events before waiting again
                while let Some(item) = rb.next() {
                    // The kernel writes ExecEvent bytes into the ring buffer map
                    // We just convert those bytes
                    let event = unsafe { &*(item.as_ptr() as *const ExecEvent) };

                    exec_handler::handle_event(
                        event,
                        &mut process_tree,
                        &user_db,
                        &config,
                        &mut correlator,
                        &mut scorer,
                        &response_engine,
                    );
                }

                // Tell AsyncFd we handled this readiness notification.
                guard.clear_ready();
            }

            // arm2
            // This arm will manage exit events data
            Ok(mut guard) = exit_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    // we will read it as u32 directly
                    let pid = unsafe { *(item.as_ptr() as *const u32)};

                    exit_handler::handle_event(pid, &mut process_tree, &mut correlator, &mut scorer);
                };


                guard.clear_ready();
            }

            //arm3
            // open events
            Ok(mut guard) = open_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    let event = unsafe {
                        &*(item.as_ptr() as *const OpenEvent)
                    };

                    open_handler::handle_event(
                        event,
                        &process_tree,
                        &config,
                        &mut correlator,
                        &mut scorer,
                        &response_engine,
                    );
                }

                guard.clear_ready();
            }

            //arm 4
            // connection events
            Ok(mut guard) = conn_fd.readable_mut() => {
                let rb = guard.get_inner_mut();

                while let Some(item) = rb.next() {
                    let event = unsafe {
                        &*(item.as_ptr() as *const ConnEvent)
                    };

                    conn_handler::handle_event(
                        event,
                        &process_tree,
                        &mut seen_network_callers,
                        &user_db,
                        &config,
                        &mut correlator,
                        &mut scorer,
                        &response_engine,
                    );

                }

                guard.clear_ready();
            }



            // arm 5
            // Shutdowen with Ctrl + C. Don't remove for now
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
                break;
            }
        }
    }
}