# Lavender
Lavender is a userspace EDR (Endpoint Detection and Response) tool that I am building from scratch. It will include small security agents written in Rust and C that hook into the Linux kernel via eBPF to detect anomalous behavior. I also plan to add a real-time dashboard that shows threat events.

## Current Features
- `execve` tracepoint monitoring with process lineage tracking
- `sched_process_exit` tracepoint monitoring for process tree cleanup
- `openat` tracepoint monitoring for sensitive file-read detection
- `connect` tracepoint monitoring for outbound network connection events (IPv4 and IPv6)
- JSON event output stream on stdout and JSON alert stream on stderr
- Runtime filtering from `lavender.toml`

## Project Layout
- ebpf: C eBPF program and Makefile
- common: Shared Rust event struct used by kernel and userspace sides
- agent: Rust userspace loader that attaches eBPF and reads ring buffer events


## Prerequisites
- Linux kernel with BTF enabled (check if `/sys/kernel/btf/vmlinux` exists)
- `bpftool`
- `clang` with BPF target support
- `libbpf` development headers (needed for `bpf_helpers.h` and `bpf_core_read.h`)
- Rust toolchain and `cargo`
- sudo or root privileges to load/attach eBPF programs
- `llvm-objdump` (optional, for disassembly)

## Build eBPF Program
From repository root:

```bash
cd ebpf
make vmlinux
make build
```
This generates:
- ebpf/vmlinux.h
- ebpf/execve.bpf.o

## Run Userspace Loader
From repository root:

```bash
sudo cargo run --manifest-path agent/Cargo.toml
```

Or from the agent directory:

```bash
cd agent
sudo cargo run --manifest-path Cargo.toml
```

On success, you should see:

```text
Lavender is watching. Ctrl+C to stop
```

## Configuration (`lavender.toml`)
Lavender uses a TOML config file at the repository root:

```text
lavender.toml
```

Current keys:
- `filters.safe_shell_launchers`: process names allowed to launch shells without alerting
- `filters.ignored_comms`: process names to skip during detection
- `filters.safe_file_readers`: process names allowed to read sensitive files without alerting

Example:

```toml
[filters]
safe_shell_launchers = ["bash", "sh", "zsh", "fish", "code"]
ignored_comms = ["cpuUsage.sh"]
safe_file_readers = ["code", "vim", "nvim", "nano"]
```

Note: the agent currently loads `../lavender.toml`, so run it from the `agent` directory to use this config path reliably.

## Save Output To JSON
From the `agent` directory, run the compiled binary directly so redirection applies cleanly:

```bash
cd agent
cargo build
```

Capture all exec events to `events.json` and all alerts to `alerts.json`:

```bash
sudo ./target/debug/lavender-loader > events.json 2> alerts.json
```

The preferred runtime command is the compiled binary path:

```bash
sudo ./target/debug/lavender-loader
```

Capture only alerts to `alerts.json` (discard normal exec stream):

```bash
sudo ./target/debug/lavender-loader 1>/dev/null 2>alerts.json
```

Capture only alerts and also see them live in terminal:

```bash
sudo ./target/debug/lavender-loader 1>/dev/null 2> >(tee alerts.json >&2)
```

Note: `./lavender-loader` may fail with "command not found" unless you copied the binary to the current directory. The default Cargo path is `./target/debug/lavender-loader`.


## Why `exec format error` happens? (What I learned)
`execve.bpf.o` is an ELF object for the eBPF virtual machine, not a native executable. It cannot be run directly with `./execve.bpf.o`.

Use it by loading it through a userspace loader (for example, a Rust/C program using libbpf) or `bpftool` attach/load commands.

## Event Streams And Map Names
The userspace loader reads from four ring buffer maps:
- `exec_events`: process exec events (`pid`, `ppid`, `comm`, `filename`)
- `exit_events`: process exit events (`pid`)
- `open_events`: file-open events (`pid`, `comm`, `filename`)
- `conn_events`: network-connect events (`pid`, `comm`, `dest_ip`, `dest_port`, `af`)

Output JSON `type` values currently emitted:
- `exec`
- `conn`
- `alert`

Alert rules currently emitted:
- `T1059 [Unexpected shell spawn]`
- `T1003 [Sensitive file read]`

Current eBPF map names are defined in `ebpf/execve.bpf.c`.

## Helpful commands
```bash
make help
make disasm
make clean
```

