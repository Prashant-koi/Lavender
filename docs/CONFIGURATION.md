# Configuration

Lavender reads a TOML config file named `lavender.toml`.

## File Discovery
Config loading order is:

1. `LAVENDER_CONFIG` if it points to an existing file
2. the nearest `lavender.toml` found by walking upward from the current working directory
3. the nearest `lavender.toml` found by walking upward from the agent executable directory
4. built-in defaults, with a warning on stderr

## Sections

### `agent`
- `agent.agent_id`: stable agent identifier used in transport payloads and subjects
- `agent.tenant_id`: tenant identifier used in NATS subjects
- `agent.nats_url`: NATS connection string
- `agent.telemetry_subject_prefix`: raw telemetry subject prefix, default `telemetry.raw`
- `agent.heartbeat_subject_prefix`: heartbeat subject prefix, default `heartbeat`
- `agent.heartbeat_interval_secs`: heartbeat publish interval

### `filters`
- `filters.safe_shell_launchers`: process names allowed to launch shells without alerting
- `filters.ignored_comms`: process names skipped before exec output/detection
- `filters.safe_file_readers`: process names allowed to read sensitive files without alerting
- `filters.shell_names`: process names treated as shells in detections and correlation
- `filters.sensitive_files`: path patterns treated as sensitive reads
- `filters.suspicious_ports`: destination ports treated as suspicious
- `filters.noisy_comms`: process names suppressed in correlation rules
- `filters.correlator_max_events`: per-process correlation buffer size
- `filters.correlator_max_age_secs`: correlation staleness window

### `response`
- `response.dry_run`: when `true`, log response intent without sending `SIGKILL`
- `response.kill_threshold`: minimum accumulated score required before kill response
- `response.protected_comms`: process-name fragments excluded from kill response

## Example

```toml
[agent]
agent_id = "dev-agent-1"
tenant_id = "dev"
nats_url = "nats://127.0.0.1:4222"
telemetry_subject_prefix = "telemetry.raw"
heartbeat_subject_prefix = "heartbeat"
heartbeat_interval_secs = 15

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

## Explicit Config Path

```bash
LAVENDER_CONFIG=./lavender.toml sudo ./target/debug/agent
```
