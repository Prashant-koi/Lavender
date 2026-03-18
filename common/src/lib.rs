#![no_std]

#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],    // process name, the kernel limits this to 16 bytes (TASK_COMM_LEN)
    pub filename: [u8; 256],
}

#[repr(C)]
pub struct ExitEvent {
    pub pid: u32,
}

#[repr(C)]
pub struct OpenEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[repr(C)]
pub struct ConnEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16], // command name
    pub daddr: [u8; 16], // the destination ip, size enough for IPv6, IPv4 uses the first 4 bytes
    pub dport: u16, // the destination port
    pub af: u16, // the address family (IPv4 or IPv6 might be other too)
}