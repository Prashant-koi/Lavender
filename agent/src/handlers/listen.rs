use common::ListenEvent;
use crate::handlers::decode_c_string;

/// listen() marks a socket passive which happens the moment it becomes a listener.
/// Only server/backdoor sockets ever call this, so it's the cleaner signal
/// We can correlate this with the bind on the same fd to learn the port.
pub fn handle_event(event: &ListenEvent) {
    let comm = decode_c_string(&event.comm);
    println!(
        "{{\"type\":\"listen\",\"ktime_ns\":{},\"pid\":{},\"uid\":{},\"comm\":{:?},\"sockfd\":{},\"backlog\":{}}}",
        event.ktime_ns, event.pid, event.uid, comm, event.sockfd, event.backlog
    );
}
