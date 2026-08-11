use common::ExecveatEvent;
use crate::handlers::decode_c_string;

const AT_EMPTY_PATH: i32 = 0x1000;

/// Phase 1: execveat is exec-from-an-fd. With AT_EMPTY_PATH + an empty pathname it
/// runs a binary straight from a file descriptor — the back half of the memfd_create
/// fileless-execution chain (T1620). Surface it locally; correlation comes later.
pub fn handle_event(event: &ExecveatEvent) {
    let comm = decode_c_string(&event.comm);
    let filename = decode_c_string(&event.filename);
    let cmdline = decode_c_string(&event.cmdline);
    // fd-exec: executing directly from a descriptor (a memfd here == fileless)
    let fd_exec = (event.flags & AT_EMPTY_PATH) != 0;
    println!(
        "{{\"type\":\"execveat\",\"ktime_ns\":{},\"pid\":{},\"ppid\":{},\"uid\":{},\"comm\":{:?},\"dirfd\":{},\"flags\":{},\"fd_exec\":{},\"filename\":{:?},\"cmdline\":{:?}}}",
        event.ktime_ns, event.pid, event.ppid, event.uid, comm,
        event.dirfd, event.flags, fd_exec, filename, cmdline
    );
}
