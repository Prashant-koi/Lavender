use common::SetidEvent;
use crate::handlers::decode_c_string;

/// a setuid-family call whose effective uid went from non-root to 0 and
/// SUCCEEDED is privilege escalation (T1548). We record the old uid at enter and
/// the return value at exit, so a real escalation is distinguishable from a failed
/// attempt or a routine privilege drop.
pub fn handle_event(event: &SetidEvent) {
    let comm = decode_c_string(&event.comm);
    let call = match event.call {
        0 => "setuid",
        1 => "setreuid",
        2 => "setresuid",
        _ => "setid",
    };
    let success = event.success == 1;
    // the escalation signal: non-root -> effective uid 0, and it worked
    let to_root = success && event.old_uid != 0 && event.new_uid == 0;
    println!(
        "{{\"type\":\"setid\",\"ktime_ns\":{},\"pid\":{},\"comm\":{:?},\"syscall\":{:?},\"old_uid\":{},\"new_uid\":{},\"success\":{},\"to_root\":{}}}",
        event.ktime_ns, event.pid, comm, call, event.old_uid, event.new_uid, success, to_root
    );
}
