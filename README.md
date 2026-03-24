# Lavender
Lavender is a userspace EDR (Endpoint Detection and Response) tool built on a full Rust + Aya stack.

The project uses:
- `aya` in userspace (`agent`)
- `aya-ebpf` in kernel eBPF programs (`lavender-ebpf`)
- shared Rust event types in `common`

## Current Features
- `execve` tracepoint monitoring with process lineage tracking
- `sched_process_exit` tracepoint monitoring for process tree cleanup
- `openat` tracepoint monitoring for sensitive file-read detection
- `connect` tracepoint monitoring for outbound network connection events (IPv4 and IPv6)
- Per-process short-term correlation buffer (`max_events`, `max_age_secs`)
- Multi-step correlation rules (reverse-shell chain, cred-access then exec, rapid spawn)
- Context-aware scoring (base rule + lineage bonus + rare parent-child bonus + sequence bonus)
- Severity labels (`INFO`, `WARNING`, `HIGH`, `CRITICAL`) derived from total score
- Active response engine with `dry_run`, `kill_threshold`, and protected-process guards
- JSON event output stream on stdout and JSON alert stream on stderr
- Runtime filtering from `lavender.toml`

## Project Layout
- `agent`: Rust userspace loader (Aya) that loads/attaches probes and consumes ring buffers
- `lavender-ebpf`: Rust eBPF probes (Aya eBPF)
- `common`: shared Rust event structs used by both sides
- `lavender.toml`: runtime filtering config


## Prerequisites
- Linux kernel with BTF enabled (check if `/sys/kernel/btf/vmlinux` exists)
- Rust toolchain and `cargo`
- `rustup` with nightly toolchain
- nightly `rust-src` component
- `bpf-linker` installed in PATH
- sudo or root privileges to load/attach eBPF programs

Recommended setup:

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

## Build
From repository root, build the userspace agent:

```bash
cargo build --package agent
```

During this build, `agent/build.rs` automatically builds `lavender-ebpf` for the BPF target with nightly and embeds the artifact path.

If you want to build only the eBPF crate directly:

```bash
cd lavender-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

## Run
From repository root:

```bash
cargo build --package agent
sudo ./target/debug/agent
```

Build as your normal user, then run the compiled binary with `sudo`.
Avoid running Cargo itself with `sudo`.

Or run only the binary directly after a prior build:

```bash
sudo ./target/debug/agent
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
- `filters.shell_names`: process names treated as shells in detections/correlation
- `filters.sensitive_files`: sensitive path patterns for file-open checks
- `filters.suspicious_ports`: destination ports treated as suspicious
- `filters.noisy_comms`: noisy process names suppressed in correlation rules
- `filters.correlator_max_events`: per-pid buffer size for correlation
- `filters.correlator_max_age_secs`: staleness window for buffered events
- `response.dry_run`: when true, print response intent without sending kill
- `response.kill_threshold`: minimum total score required before response
- `response.protected_comms`: comm patterns excluded from kill response

Example:

```toml
[filters]
safe_shell_launchers = ["tmux", "alacritty", "kitty", "sshd", "sudo", "su", "login", "Hyprland", "code"]
ignored_comms = ["cpuUsage.sh"]
safe_file_readers = ["sshd", "sudo", "passwd", "shadow", "pam", "bash", "zsh", "sh", "code", "vim", "nvim", "nano"]
shell_names = ["bash", "sh", "zsh", "fish", "dash"]
sensitive_files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/authorized_keys", "/.bash_history", "/.zsh_history", "/root/.ssh"]
suspicious_ports = [4444, 1337, 9001, 9999, 6666, 31337, 5555]
noisy_comms = ["code", "cpuUsage", "cargo", "rustc", "make"]
correlator_max_events = 20
correlator_max_age_secs = 30

[response]
dry_run = true
kill_threshold = 200
protected_comms = ["systemd", "sshd", "sudo", "init", "lavender", "agent", "kernel"]
```

The agent reads `lavender.toml` from the current working directory.
When running from the repository root (recommended), this works out of the box.

## Save Output To JSON
Capture all normal events to `events.json` and alerts to `alerts.json`:

```bash
sudo ./target/debug/agent > events.json 2> alerts.json
```

The preferred runtime command is the compiled binary path:

```bash
sudo ./target/debug/agent
```

Capture only alerts to `alerts.json` (discard normal exec stream):

```bash
sudo ./target/debug/agent 1>/dev/null 2>alerts.json
```

Capture only alerts and also see them live in terminal:

```bash
sudo ./target/debug/agent 1>/dev/null 2> >(tee alerts.json >&2)
```

Note: the default Cargo output path for this package is `./target/debug/agent`.


## Why `exec format error` happens? (What I learned)
`lavender-ebpf` (the BPF target artifact) is an ELF object for the eBPF virtual machine, not a native userspace executable.

It cannot be run directly.
It must be loaded by the Rust userspace loader (`agent`) through Aya.

## Event Streams And Map Names
The userspace loader reads from four ring buffer maps:
- `EXEC_EVENTS`: process exec events (`pid`, `ppid`, `comm`, `filename`)
- `EXIT_EVENTS`: process exit events (`pid`)
- `OPEN_EVENTS`: file-open events (`pid`, `comm`, `filename`)
- `CONN_EVENTS`: network-connect events (`pid`, `comm`, `dest_ip`, `dest_port`, `af`)

Output JSON `type` values currently emitted:
- `exec`
- `conn`
- `alert`

Response events are emitted as JSON on stderr with `kind: "response"`.

Scored alerts also include optional score breakdown fields:
- `base_score`
- `lineage_bonus`
- `rarity_bonus`
- `sequence_bonus`

Alert rules currently emitted:
- `T1059 [Unexpected shell spawn]`
- `T1003 [Sensitive file read]`
- `T1071 [Connection to suspicious port]`
- `T1059 [Shell making outbound connection]`
- `T1071 [First time Network Caller]`
- `CHAIN Reverse shell behaviour`
- `CHAIN Credential access then execution`
- `CHAIN Rapid process spawning`

Current eBPF map/program names are defined in `lavender-ebpf/src/main.rs`.

