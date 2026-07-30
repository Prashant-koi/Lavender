use common::BpfEvent;
use crate::handlers::decode_c_string;

fn bpf_cmd_name(cmd: u32) -> &'static str {
    match cmd {
        0 => "MAP_CREATE",
        5 => "PROG_LOAD",
        18 => "BTF_LOAD",
        _ => "other",
    }
}

pub fn handle_event(event: &BpfEvent) {
    let comm = decode_c_string(&event.comm);
    println!(
        "{{\"type\":\"bpf\",\"ktime_ns\":{},\"pid\":{},\"uid\":{},\"comm\":{:?},\"cmd\":{},\"cmd_name\":{:?}}}",
        event.ktime_ns, event.pid, event.uid, comm, event.cmd, bpf_cmd_name(event.cmd)
    );
}
