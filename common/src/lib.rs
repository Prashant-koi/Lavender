#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],    // process name, the kernel limits this to 16 bytes (TASK_COMM_LEN)
    pub filename: [u8; 256],
}