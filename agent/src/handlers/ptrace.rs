use common::PtraceEvent;
use crate::handlers::decode_c_string;

pub fn handle_event(event: &PtraceEvent) {
    let comm = decode_c_string(&event.comm);
    println!(
        "{{\"type\":\"ptrace\",\"ktime_ns\":{},\"pid\":{},\"uid\":{},\"comm\":{:?},\"target_pid\":{},\"request\":{}}}",
        event.ktime_ns, event.pid, event.uid, comm, event.target_pid, event.request
    );
}
