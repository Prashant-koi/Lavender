# Configuration

Lavender uses a TOML config file named `lavender.toml`.

## File Location
Recommended location is the repository root:

```text
lavender.toml
```

## Config Loading Order
Config loading order is currently:
- `LAVENDER_CONFIG` environment variable path (if set and file exists)
- nearest `lavender.toml` found by searching upward from current working directory
- nearest `lavender.toml` found by searching upward from the agent executable directory
- built-in defaults (with a warning on stderr) if no config file is found

## Keys

### filters
- `filters.safe_shell_launchers`: process names allowed to launch shells without alerting
- `filters.ignored_comms`: process names to skip during detection
- `filters.safe_file_readers`: process names allowed to read sensitive files without alerting
- `filters.shell_names`: process names treated as shells in detections/correlation
- `filters.sensitive_files`: sensitive path patterns for file-open checks
- `filters.suspicious_ports`: destination ports treated as suspicious
- `filters.noisy_comms`: noisy process names suppressed in correlation rules
- `filters.correlator_max_events`: per-pid buffer size for correlation
- `filters.correlator_max_age_secs`: staleness window for buffered events

### response
- `response.dry_run`: when true, print response intent without sending kill
- `response.kill_threshold`: minimum total score required before response
- `response.protected_comms`: comm patterns excluded from kill response

## Example

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

## Explicit Config Path
Run with explicit config path:

```bash
LAVENDER_CONFIG=./lavender.toml sudo ./target/debug/agent
```
