use common::ConnEvent;

//every event will get a unix timestamp
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

//formatting of ip from the 4/16 byts of IPv4/IPv6
pub fn format_ip(event: &ConnEvent) -> String {
    if event.af == 2 {
        //IPV4, which is first 4 bytes
        format!(
            "{}.{}.{}.{}",
            event.daddr[0],
            event.daddr[1],
            event.daddr[2],
            event.daddr[3],
        )
    } else {
        //IPv6, all 16 bytes as hex pairs
        let b = &event.daddr;
        format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
            b[13], b[14], b[15]
        ) // props to Claude for writing this!
    }
}
