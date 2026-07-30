#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

mod vmlinux;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task_btf,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    }, 
    macros::{lsm, map, tracepoint}, 
    maps::{HashMap, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use common::{BpfEvent, ConnEvent, ExecEvent, ExitEvent, MemfdEvent, ModuleLoadEvent, OpenEvent, PtraceEvent};
use vmlinux::{ bpf_map, task_struct };

// all the maps

#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CONN_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static PTRACE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static MODULE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static BPF_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static MEMFD_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

//pids the agent is allowed to keep alive which is written from userspace at startup
//since we do not know the agent pid till runtime
#[map]
static PROTECTED_PID: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

// anti kill
// THESE ARE ARCH DEPENDENT
const SIGKILL: i32 = 9;
const SIGSTOP: i32 = 19;
const EPERM: i32 = 1;

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    match try_task_kill(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // this is a bit dangerious since this can allow kill if bpf_probe_read_kernel() fails/errors
    }
}

fn try_task_kill(ctx: &LsmContext) -> Result<i32, i64> {
    // arg0 = target task_Struct*, arg2 = signal number
    let target: *const task_struct = unsafe { ctx.arg(0) };
    let sig: i32 = unsafe { ctx.arg(2) };

    // leave SIGTERM guard the SIGKILL and SIGSTOP
    if sig != SIGKILL && sig != SIGSTOP {
        return Ok(0);
    }

    // global tgid of the target procees which the userspace stored
    let target_tgid = unsafe {
        bpf_probe_read_kernel::<i32>(core::ptr::addr_of!((*target).tgid))? 
    } as u32;

    // if not a protected pid then normal operations
    if unsafe {PROTECTED_PID.get(&target_tgid)}.is_none() {
        return Ok(0);
    }

    // let the protected processes singnal itslef so they can self stop
    let sender = (bpf_get_current_pid_tgid() >> 32) as u32;
    if sender == target_tgid {
        return  Ok(0);
    }

    //anyone esle tryign to SIGKILL or SIGSTOP a protected pid is denied
    Ok(-EPERM)
}

// Lower Endian encoding (since x86_64/arch64 are LE) of the kernel mal name "PROTECTED_PID\0\0\0"\
const PROTECTED_MAP_NAME0: u64 = 0x45544345544F5250;
const PROTECTED_MAP_NAME1: u64 = 0x0000004449505F44;

// security_bpf_map(struct bpf_map *map, fmode_t fmode)
// fires whenever a process tried to get and fd to a bpf map
// we refuse to hand out PROTECTED_PID map to anyone but the agent so an attacker can't open it and
// delete the agents entry to unprotect it
#[lsm(hook = "bpf_map")]
pub fn bpf_map(ctx: LsmContext) -> i32 {
    match try_bpf_map(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_bpf_map(ctx: &LsmContext) -> Result<i32, i64> {
    let map: *const bpf_map = unsafe { ctx.arg(0) };

    // we read the kernels 16-byte name for this map as two u64s
    // so there will bne no array indexing and bound checking
    let name_ptr =  unsafe { core::ptr::addr_of!((*map).name)  as *const u64 };
    let n0 = unsafe { bpf_probe_read_kernel::<u64>(name_ptr)?};
    let n1 = unsafe { bpf_probe_read_kernel::<u64>(name_ptr.add(1))?};

    // if not our protected map then we will allow normallu
    if n0 != PROTECTED_MAP_NAME0 || n1 != PROTECTED_MAP_NAME1 {
        return Ok(0);
    }

    let sender = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { PROTECTED_PID.get(&sender) }.is_some() {
        return Ok(0);
    }

    Ok(-EPERM)
}

// security_ptrace_access_check(struct task_struct *child, unsigned int mode)
// stops an attacker from ptrace attaching to the agent and injecting code that would
// make it cloase it own bpf links or clear its own protection
#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match try_ptrace_access_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_ptrace_access_check(ctx: &LsmContext) -> Result<i32, i64> {
    let child: *const task_struct = unsafe { ctx.arg(0) };
    let child_tgid = unsafe {
        bpf_probe_read_kernel::<i32>(core::ptr::addr_of!((*child).tgid))?
    } as u32;

    if unsafe { PROTECTED_PID.get(&child_tgid) }.is_none() {
        return Ok(0);
    }

    // allow agent to trace itslef and we will deny others
    let sender = (bpf_get_current_pid_tgid() >> 32) as u32;
    if sender == child_tgid {
        return Ok(0);
    }

    Ok(-EPERM)
}

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

        (*data).ktime_ns = bpf_ktime_get_ns();
        (*data).pid  = (id >> 32) as u32;
        (*data).uid  = (ugid & 0xFFFFFFFF) as u32;
        (*data).comm = comm;
        (*data).ppid = current_ppid().unwrap_or(0);
        (*data).cmdline = [0u8; 512]; // rigng buffer memory is unitizlized zero so it null terminates

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

        // args[1] = argv pointer (char **argv)
        let argv_ptr = match ctx.read_at::<u64>(24) {
            Ok(ptr) => ptr as *const *const u8,
            Err(_) => {
                e.submit(0);
                return Ok(());
            }
        };

        // we take one explicit &mut to the buffer and index that, so we don't create
        // an implicit autoref through the raw-pointer deref (which rustc rejects)
        let buf = &mut (*data).cmdline;

        let mut cursor: usize = 0;
        let mut i: usize = 0;
        while i < 32 {
            if cursor >= 500 {
                break;
            }

            let arg_addr = match bpf_probe_read_user(argv_ptr.add(i)) {
                Ok(a) => a,
                Err(_) => break,
            };
            if arg_addr.is_null() {
                break; // end of argv
            }

            // we mask start so the verifier sees an in-bounds destination slice
            let start = cursor & 511;
            let n = match bpf_probe_read_user_str_bytes(arg_addr, &mut buf[start..]) {
                Ok(read) => read.len(),
                Err(_) => break,
            };

            cursor += n;
            if cursor < 511 {
                buf[cursor & 511] = b' ';
                cursor += 1;
            }

            i += 1;
        }
    }

    e.submit(0);
    Ok(())
}

// function top get the current ppid this is why we have to have 
// vmlinux.rs
fn current_ppid() -> Result<u32, i64> {
    unsafe {
        // bpf_get_current_task_btf gives typed pointer to current kernel task_struct
        // for the process running the exec tracepoint
        let task = bpf_get_current_task_btf() as *const task_struct;
        if task.is_null() {
            return Err(1);
        }

        // bpf_probe_read_kernel copies a kernel field into local eBPF stack memory
        // so we read reak_parent so that we can get the parent task 
        let parent = bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_parent))
            .map_err(|err| err as i64)?;
        if parent.is_null() {
            return Err(1);
        }

        // Then we read tgid which is what WE want to see as ppid
        let ppid = bpf_probe_read_kernel(core::ptr::addr_of!((*parent).tgid))
            .map_err(|err| err as i64)?;
        Ok(ppid as u32)
    }
}

// this function will handle the exit of processes this is that tracepoint

#[tracepoint]
pub fn handle_exit(_ctx: TracePointContext) -> i32 {
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    let tid = id as u32;

    // sched_process_exit fires for evry thread that exits, not just the process
    // emitting on just the worker-thread exit would evict state for a process that is still alive 
    // so we only report when the main thread (tid == tgid) goes down which indicates the death of the actual process
    if tid != tgid {
        return 0;
    }

    let mut slot = match EXIT_EVENTS.reserve::<ExitEvent>(0) {
        Some(s) => s,
        None    => return 0,
    };

    unsafe {
        let data = slot.as_mut_ptr();
        (*data).ktime_ns = bpf_ktime_get_ns();
        (*data).pid = tgid;
    }

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

        (*data).ktime_ns = bpf_ktime_get_ns();
        (*data).pid = (id >> 32) as u32;
        (*data).comm = comm;
        (*data).flags = ctx.read_at::<u64>(32).unwrap_or(0) as i32; // Read the flag

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

        (*data).ktime_ns = bpf_ktime_get_ns();
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

// ptrace

#[tracepoint]
pub fn handle_ptrace(ctx: TracePointContext) -> i32 {
    match try_handle_ptrace(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

fn try_handle_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    let mut e = match PTRACE_EVENTS.reserve::<PtraceEvent>(0) {
        Some(e) => e,
        None    => return Ok(()),
    };

    let id   = bpf_get_current_pid_tgid();
    let ugid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        let data = e.as_mut_ptr();

        (*data).ktime_ns   = bpf_ktime_get_ns();
        (*data).pid        = (id >> 32) as u32;
        (*data).uid        = (ugid & 0xFFFFFFFF) as u32;
        (*data).comm       = comm;
        // sys_enter_ptrace args: long request(16), long pid(24), ulong addr(32), ulong data(40)
        (*data).request    = ctx.read_at::<u64>(16).unwrap_or(0) as i32;
        (*data).target_pid = ctx.read_at::<u64>(24).unwrap_or(0) as u32;
    }

    e.submit(0);
    Ok(())
}

// module load — T1547.006 rootkit / LKM loading

#[inline(always)]
fn emit_module_load(ctx: &TracePointContext, is_finit: u8, param_off: usize) {
    let mut e = match MODULE_EVENTS.reserve::<ModuleLoadEvent>(0) {
        Some(e) => e,
        None    => return,
    };

    let id   = bpf_get_current_pid_tgid();
    let ugid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        let data = e.as_mut_ptr();

        (*data).ktime_ns = bpf_ktime_get_ns();
        (*data).pid      = (id >> 32) as u32;
        (*data).uid      = (ugid & 0xFFFFFFFF) as u32;
        (*data).comm     = comm;
        (*data).is_finit = is_finit;
        (*data).params   = [0u8; 128];

        // module param string; may be null, in which case params stays empty
        if let Ok(pv) = ctx.read_at::<u64>(param_off) {
            if pv != 0 {
                let _ = bpf_probe_read_user_str_bytes(pv as *const u8, &mut (*data).params);
            }
        }
    }

    e.submit(0);
}

#[tracepoint]
pub fn handle_finit_module(ctx: TracePointContext) -> i32 {
    // finit_module(fd, param_values, flags): param_values at offset 24
    emit_module_load(&ctx, 1, 24);
    0
}

#[tracepoint]
pub fn handle_init_module(ctx: TracePointContext) -> i32 {
    // init_module(umod, len, param_values): param_values at offset 32
    emit_module_load(&ctx, 0, 32);
    0
}

// bpf() syscall observation, T1562.001 attacker loading BPF to blind tooling.
// security_bpf(int cmd, union bpf_attr *attr, unsigned int size)
#[lsm(hook = "bpf")]
pub fn observe_bpf(ctx: LsmContext) -> i32 {
    let _ = try_observe_bpf(&ctx);
    0 // we never deny we are just observing
}

fn try_observe_bpf(ctx: &LsmContext) -> Result<(), i64> {
    let id  = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;

    // skip the agent's own bpf() usage so we don't drown in our own noise
    if unsafe { PROTECTED_PID.get(&pid) }.is_some() {
        return Ok(());
    }

    let mut e = match BPF_EVENTS.reserve::<BpfEvent>(0) {
        Some(e) => e,
        None    => return Ok(()),
    };

    let ugid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        let data = e.as_mut_ptr();

        (*data).ktime_ns = bpf_ktime_get_ns();
        (*data).pid      = pid;
        (*data).uid      = (ugid & 0xFFFFFFFF) as u32;
        (*data).comm     = comm;
        (*data).cmd      = ctx.arg(0); // int cmd (arg 0 of security_bpf)
    }

    e.submit(0);
    Ok(())
}

// memfd_create

#[tracepoint]
pub fn handle_memfd_create(ctx: TracePointContext) -> i32 {
    match try_handle_memfd_create(&ctx) {
        Ok(_)  => 0,
        Err(_) => 0,
    }
}

fn try_handle_memfd_create(ctx: &TracePointContext) -> Result<(), i64> {
    let mut e = match MEMFD_EVENTS.reserve::<MemfdEvent>(0) {
        Some(e) => e,
        None    => return Ok(()),
    };

    let id   = bpf_get_current_pid_tgid();
    let ugid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    unsafe {
        let data = e.as_mut_ptr();

        (*data).ktime_ns = bpf_ktime_get_ns();
        (*data).pid      = (id >> 32) as u32;
        (*data).uid      = (ugid & 0xFFFFFFFF) as u32;
        (*data).comm     = comm;
        // memfd_create(const char *name, unsigned int flags): name @ 16, flags @ 24
        (*data).flags    = ctx.read_at::<u64>(24).unwrap_or(0) as u32;
        (*data).name     = [0u8; 64];

        if let Ok(name_ptr) = ctx.read_at::<u64>(16) {
            if name_ptr != 0 {
                let _ = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut (*data).name);
            }
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
