use common::MemfdEvent;
use crate::handlers::decode_c_string;

// memfd_create backs a file that lives only in RAM so there is no disk path
// we need to pair it with an execveat of that fd and you have fileless execution 
pub fn handle_event(event: &MemfdEvent) {
    let comm = decode_c_string(&event.comm);
    let name = decode_c_string(&event.name);
    println!(
        "{{\"type\":\"memfd_create\",\"ktime_ns\":{},\"pid\":{},\"uid\":{},\"comm\":{:?},\"name\":{:?},\"flags\":{}}}",
        event.ktime_ns, event.pid, event.uid, comm, name, event.flags
    );
}
