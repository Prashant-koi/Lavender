pub mod detection;
pub mod output;
pub mod config;
pub mod users;

use aya::{Bpf, include_bytes_aligned};
use aya::programs::TracePoint;
use aya::maps::RingBuf;
use common::{ExecEvent, OpenEvent, ConnEvent};
use std::collections::{HashMap, HashSet};
use tokio::io::unix::AsyncFd;

#[derive(Clone, Debug)]
pub struct ProcessNode {
    pid: u32,
    ppid: u32,
    comm: String,
    filename: String,
}

fn build_ancestry_chain(pid: u32, tree: &HashMap<u32, ProcessNode>) -> String {
    let mut chain = vec![];
    let mut current_pid = pid;

    //we will walk upward through parents and go max of 8 levels
    // max limit to stop inf loops in case the data is weird
    for _ in 0..8 {
        match tree.get(&current_pid) {
            Some(node) => {
                chain.push(node.comm.clone());
                if node.ppid == 0 || node.ppid == current_pid {
                    //either we reached init or a cycle
                    break;
                }
                current_pid = node.ppid;
            }
            None => break,
        }
    }

    // reverse the chian since we built it button up
    chain.reverse();
    chain.join("=>")
}

#[tokio::main]
async fn main() {
    // we will load the config first
    let config = config::Config::load("lavender.toml");
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

                    // eBPF sends fixed-size null-terminated byte arrays.
                    // Convert to UTF-8 strings and strip trailing null bytes.
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("?")
                        .trim_end_matches('\0')
                        .to_string();

                    let filename = std::str::from_utf8(&event.filename)
                        .unwrap_or("?")
                        .trim_end_matches('\0')
                        .to_string();

                    let user = user_db.resolve(event.uid);

                    // we will keep latest process metadata so we can reconstruct lineage
                    process_tree.insert(
                        event.pid,
                        ProcessNode {
                            pid: event.pid,
                            ppid: event.ppid,
                            comm: comm.to_string(),
                            filename: filename.to_string(),
                        },
                    );

                    let ancestry = build_ancestry_chain(event.pid, &process_tree);

                    //we will skip the ignored processes(those mentioned in the lavender.toml)
                    if config.filters.ignored_comms.iter().any(|s| comm.contains(s.as_str())) {
                        continue;
                    }
                
                    output::print_exec(event.pid, event.ppid, &user, &comm, &filename, &ancestry);


                    //checking if the spawned process has a suspicious parent or is supicious refer detection.rs
                    if let Some(alert) = detection::check_suspicious_shell_spawn(
                        &comm,
                        &filename,
                        event.pid,
                        &ancestry,
                        &config.filters.safe_shell_launchers,
                    ) {
                        // I will print it in red so that the Alert stands out
                        output::print_alert(alert.pid, alert.rule, &alert.detail, &alert.ancestry);
                    }
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
                    
                    //remove from tree
                    if process_tree.remove(&pid).is_some() {
                        // uncomment while testing, NOTE TO SELF
                        // println!("[exit     {:>6}] removed from tree", pid)
                    }

                    // temporary debug line 
                    // println!("[tree size: {}]", process_tree.len());
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

                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("?")
                        .trim_end_matches('\0')
                        .to_string();

                    let filename = std::str::from_utf8(&event.filename)
                        .unwrap_or("?")
                        .trim_end_matches('\0')
                        .to_string();

                    // do not print every file open that will flood the whole thing
                    // so only run the detection and print if fires
                    if let Some(alert) = detection::check_sensitive_file_read(
                        &comm,
                        &filename,
                        event.pid,
                        "unknown", // no ancestory for open evtns yet
                        &config.filters.safe_file_readers
                    ) {
                        output::print_alert(alert.pid, alert.rule, &alert.detail, &alert.ancestry);
                    }
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

                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("?")
                        .trim_end_matches('\0')
                        .to_string();

                    //we will skip port 0 as they are internal socket operations
                    if event.dport == 0 {
                        continue;
                    }

                    //if localhost also skip
                    if event.af == 2 && event.daddr[0] == 27 {
                        continue;
                    }

                    let user = user_db.resolve(event.uid);
                    let dest_ip = output::format_ip(event);

                    output::print_conn(event, &comm, &user);

                    //check if the connection is has been made for the first time
                    if !seen_network_callers.contains(&comm) {
                        seen_network_callers.insert(comm.clone());
                        //print this if it is the first time command has made an network connection
                        output::print_alert(event.pid, 
                            "T1071 [First time Network Caller]",
                            &format!("'{}' made its first observed outbound connection to {}:{}",
                                comm, dest_ip, event.dport),
                            "unknown");
                    }

                    // Rule 1, there is high confidence of suspicious network connection
                    if let Some(alert) = detection::check_shell_network_connection(
                        &comm,
                        &dest_ip,
                        event.dport,
                        event.pid,
                        "unknown"
                    ) {
                        output::print_alert(alert.pid, alert.rule, &alert.detail, &alert.ancestry);
                    }

                    // Rule 2, there is a midium level of confidence in this case
                    if let Some(alert) = detection::check_suspicious_port(
                        &comm,
                        &dest_ip,
                        event.dport,
                        event.pid,
                        "unknown",
                    ) {
                        output::print_alert(alert.pid, alert.rule, &alert.detail, &alert.ancestry);
                    }

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