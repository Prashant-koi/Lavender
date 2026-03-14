use aya::Ebpf;
use aya::programs::TracePoint;
use aya::maps::RingBuf;
use common::ExecEvent;
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() {
    // We will Load the compiled eBPF object file.
    // This contains the kernel-side program and maps.
    let mut bpf = Ebpf::load_file("../ebpf/execve.bpf.o").unwrap();

    // Grab the tracepoint program by name and cast it to TracePoint
    // THis way we can load and attach it
    let program: &mut TracePoint = bpf
        .program_mut("handle_execve")
        .unwrap()
        .try_into()
        .unwrap();

    // We will load program into the kernel and attach it to execve tracepoint.
    program.load().unwrap();
    program.attach("syscalls", "sys_enter_execve").unwrap();

    // Get a handle to the ring buffer map used to send events
    // from eBPF (from the kernel space) to this user-space process
    let ring = RingBuf::try_from(bpf.map_mut("events").unwrap()).unwrap();

    // Wrap ring buffer in AsyncFd so tokio can await readiness
    // without blocking the async runtime.
    let mut ring_fd = AsyncFd::new(ring).unwrap();

    println!("Lavender is watching. Ctrl+C to stop");

    loop {
        tokio::select! {
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
                        .trim_end_matches('\0');

                    let filename = std::str::from_utf8(&event.filename)
                        .unwrap_or("?")
                        .trim_end_matches('\0');

                    println!("[pid {}] {} executed: {}", event.pid, comm, filename);
                }

                // Tell AsyncFd we handled this readiness notification.
                guard.clear_ready();
            }

            // Shutdowen with Ctrl + C. Don't remove for now
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
                break;
            }
        }
    }
}