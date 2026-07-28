use common::ModuleLoadEvent;
use crate::handlers::decode_c_string;

pub fn handle_event(event: &ModuleLoadEvent) {
    let comm = decode_c_string(&event.comm);
    let params = decode_c_string(&event.params);
    let syscall = if event.is_finit == 1 { "finit_module" } else { "init_module" };
    println!(
        "{{\"type\":\"module_load\",\"ktime_ns\":{},\"pid\":{},\"uid\":{},\"comm\":{:?},\"syscall\":{:?},\"params\":{:?}}}",
        event.ktime_ns, event.pid, event.uid, comm, syscall, params
    );
}
