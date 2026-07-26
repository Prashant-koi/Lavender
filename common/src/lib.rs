#![no_std]

#[cfg(feature = "transport")]
extern crate alloc;

#[cfg(feature = "transport")]
pub mod transport;
#[repr(C)]
pub struct ExecEvent {
    pub ktime_ns: u64, // monotonic kernel time (bpf_ktime_get_ns) at event we will use to reconstruct ordering
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],    // process name, the kernel limits this to 16 bytes (TASK_COMM_LEN)
    pub filename: [u8; 256],
    pub cmdline: [u8; 512], // was argv1[128] + argv2[128]; now the full argv joined into one buffer for sigma rules
} 

#[repr(C)]
pub struct ExitEvent {
    pub ktime_ns: u64, // monotonic kernel time (bpf_ktime_get_ns) at event we will use use to reconstruct ordering
    pub pid: u32,
}

#[repr(C)]
pub struct OpenEvent {
    pub ktime_ns: u64, // monotonic kernel time (bpf_ktime_get_ns) at event we will use to reconstruct ordering
    pub pid: u32,
    pub flags: i32, // openat flags like 0_WRONLY/O_CREAT to know read vs write/create
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[repr(C)]
pub struct ConnEvent {
    pub ktime_ns: u64, // monotonic kernel time (bpf_ktime_get_ns) at event we will use tjs to reconstruct ordering
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16], // command name
    pub daddr: [u8; 16], // the destination ip, size enough for IPv6, IPv4 uses the first 4 bytes
    pub dport: u16, // the destination port
    pub af: u16, // the address family (IPv4 or IPv6 might be other too)
}