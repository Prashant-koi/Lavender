#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user, bpf_probe_read_user_str_bytes
    }, macros::{map, tracepoint}, maps::RingBuf, programs::TracePointContext
};
use common::{ConnEvent, ExecEvent, ExitEvent, OpenEvent};

// all the maps

#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CONN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// handle_execve

#[tracepoint]
pub fn handle_execve(ctx: TracePointContext) -> i32 {
    match try_handle_execve(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,  // we will always return 0 and never crash
    }
}

fn try_handle_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let mut e = match EXEC_EVENTS.reserve::<ExecEvent>(0) {
        Some(e) => e,
        None    => return Ok(()), // if buffer get full then we will frop it
    };

    let id   = bpf_get_current_pid_tgid();
    let ugid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        let data = e.as_mut_ptr();

        (*data).pid  = (id >> 32) as u32;
        (*data).uid  = (ugid & 0xFFFFFFFF) as u32;
        (*data).comm = comm;
        (*data).ppid = 0; // will resolve this in userspace side don't even try doing that here please

        // args[0] = filename pointer 
        let filename_ptr = match ctx.read_at::<u64>(16) {
            Ok(ptr) => ptr as *const u8,
            Err(_) => {
                e.discard(0);
                return Ok(());
            }
        };

        if bpf_probe_read_user_str_bytes(filename_ptr, &mut (*data).filename).is_err() {
            e.discard(0);
            return Ok(());
        }
    }

    e.submit(0);
    Ok(())
}

// this function will handle the exit of processes this is that tracepoint

#[tracepoint]
pub fn handle_exit(_ctx: TracePointContext) -> i32 {
    let mut slot = match EXIT_EVENTS.reserve::<ExitEvent>(0) {
        Some(s) => s,
        None    => return 0,
    };

    let id = bpf_get_current_pid_tgid();
    unsafe { (*slot.as_mut_ptr()).pid = (id >> 32) as u32; }

    slot.submit(0);
    0
}

// open

#[tracepoint]
pub fn handle_open(ctx: TracePointContext) -> i32 {
    match try_handle_open(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

fn try_handle_open(ctx: &TracePointContext) -> Result<(), i64> {
    let o = match OPEN_EVENTS.reserve::<OpenEvent>(0) {
        Some(o) => o,
        None    => return Ok(()),
    };

    let id = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        let data = o.as_ptr() as *mut OpenEvent;

        (*data).pid = (id >> 32) as u32;
        (*data).comm = comm;

        // args[1] = pathname
        let filename_ptr = match ctx.read_at::<u64>(24) {
            Ok(ptr) => ptr as *const u8,
            Err(_) => {
                o.discard(0);
                return Ok(());
            }
        };

        if bpf_probe_read_user_str_bytes(filename_ptr, &mut (*data).filename).is_err() {
            o.discard(0);
            return Ok(());
        }
    }

    o.submit(0);
    Ok(())
}

// connect

#[tracepoint]
pub fn handle_connect(ctx: TracePointContext) -> i32 {
    match try_handle_connect(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

fn try_handle_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let mut e = match CONN_EVENTS.reserve::<ConnEvent>(0) {
        Some(e) => e,
        None    => return Ok(()),
    };

    let id   = bpf_get_current_pid_tgid();
    let ugid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

     unsafe {
        let data = e.as_mut_ptr();

        (*data).pid   = (id >> 32) as u32;
        (*data).uid   = (ugid & 0xFFFFFFFF) as u32;
        (*data).comm  = comm;
        (*data).daddr = [0u8; 16];
        (*data).dport = 0;

        // args[1] = sockaddr pointer — offset 24
        let addr_ptr = match ctx.read_at::<u64>(24) {
            Ok(ptr) => ptr as *const u8,
            Err(_) => {
                e.discard(0);
                return Ok(());
            }
        };

        // read address family which is the first 2 bytes of any sockaddr
        let af: u16 = match bpf_probe_read_user(addr_ptr as *const u16) {
            Ok(v) => v,
            Err(_) => {
                e.discard(0);
                return Ok(());
            }
        };
        (*data).af = af;

        if af == 2 {
            // AF_INET — IPv4
            // sockaddr_in layout: u16 family, u16 port, u32 addr
            // port is at byte offset 2, addr at byte offset 4
            let port: u16 = match bpf_probe_read_user(addr_ptr.add(2) as *const u16) {
                Ok(v) => v,
                Err(_) => {
                    e.discard(0);
                    return Ok(());
                }
            };
            (*data).dport = u16::from_be(port);

            let addr: u32 = match bpf_probe_read_user(addr_ptr.add(4) as *const u32) {
                Ok(v) => v,
                Err(_) => {
                    e.discard(0);
                    return Ok(());
                }
            };
            // store IPv4 as first 4 bytes of daddr
            let daddr = &mut (*data).daddr;
            daddr[..4].copy_from_slice(&addr.to_ne_bytes());

        } else if af == 10 {
            // AF_INET6 — IPv6
            // sockaddr_in6 layout: u16 family, u16 port, u32 flowinfo, u8[16] addr
            // port at offset 2, addr at offset 8
            let port: u16 = match bpf_probe_read_user(addr_ptr.add(2) as *const u16) {
                Ok(v) => v,
                Err(_) => {
                    e.discard(0);
                    return Ok(());
                }
            };
            (*data).dport = u16::from_be(port);

            // read all 16 bytes of IPv6 address
            let addr: [u8; 16] = match bpf_probe_read_user(addr_ptr.add(8) as *const [u8; 16]) {
                Ok(v) => v,
                Err(_) => {
                    e.discard(0);
                    return Ok(());
                }
            };
            (*data).daddr = addr;

        } else {
            e.discard(0);
            return Ok(());
        }
    }

    e.submit(0);
    Ok(())
}

// required — eBPF programs must declare a panic handler
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}