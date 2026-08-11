use common::BindEvent;
use crate::handlers::decode_c_string;

fn format_addr(af: u16, addr: &[u8; 16]) -> String {
    if af == 2 {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    } else {
        let b = addr;
        format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

// bind() claims a local IP:port for a socket which is the address a backdoor
// listener grabs. we can pair it with listen() on the same fd and then we have an inbound listener 
pub fn handle_event(event: &BindEvent) {
    let comm = decode_c_string(&event.comm);
    let addr = format_addr(event.af, &event.addr);
    println!(
        "{{\"type\":\"bind\",\"ktime_ns\":{},\"pid\":{},\"uid\":{},\"comm\":{:?},\"addr\":{:?},\"port\":{},\"af\":{}}}",
        event.ktime_ns, event.pid, event.uid, comm, addr, event.port, event.af
    );
}
