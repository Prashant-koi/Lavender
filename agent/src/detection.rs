// For detection rules

pub struct Alert {
    pub pid: u32,
    pub rule: &'static str,
    pub detail: String,
    pub ancestry: String,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// patterns that usually show encoded/obfuscated execution or payload fetch-and-run behavior
const OBFUSCATED_PATTERNS: &[&str] = &[
    "base64",
    "$(curl",
    "$(wget",
    "|bash",
    "|sh",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -e",
    "/dev/tcp",
    "eval",
    "exec(",
    "frombase64string",
];

pub fn check_suspicious_shell_spawn(
    launcher_comm: &str,
    target_filename: &str,
    event_pid: u32,
    ancestry: &str,
    safe_launchers: &[String],
    shell_names: &[String],
) -> Option<Alert> {
    let target_base = basename(target_filename);

    //check if the new process is shell
    let target_is_shell = shell_names.iter().any(|s| target_base == s);
    if !target_is_shell {
        return None
    }

    //allow known normal launchers
    let laucher_is_safe = safe_launchers.iter().any(|s| launcher_comm.contains(s))
        || shell_names.iter().any(|s| launcher_comm.contains(s.as_str()));
    if laucher_is_safe {
        return None;
    }

    // by the time we reach this part we know that there is something sus going on so we will fire alert
    // Honestly this might be a bad approach we will see tho
    Some(Alert { 
        pid: event_pid, 
        rule: "T1059 [Unexpected shell spawn]", 
        detail: format!("'{}' executed shell target ({})", launcher_comm, target_base), 
        ancestry: ancestry.to_string() 
    })
}

pub fn check_sensitive_file_read (
    comm: &str,
    filename: &str,
    event_pid: u32,
    ancestry: &str,
    safe_readers: &[String],
    sensitive_files: &[String],
) -> Option<Alert> {
    // check if it is sensitive file
    // i will use contains() instead of == because path mighht be absolute
    let is_sensitve = sensitive_files.iter().any(|s| filename.contains(s));
    if !is_sensitve {
        return  None;
    }

    let is_safe = safe_readers.iter().any(|s| comm.contains(s.as_str()));
    if is_safe {
        return None;
    }

    Some(Alert { 
        pid: event_pid , 
        rule: "T1003 [Sensitive file read]",
        detail: format!("'{}' opened sensitive file: {}", comm, filename), 
        ancestry: ancestry.to_string(),
    })
}

pub fn check_shell_network_connection(
    comm: &str,
    dest_ip: &str,
    dest_port: u16,
    event_pid: u32,
    ancestry: &str,
    shell_names: &[String],
) -> Option<Alert> {
    //check if process is a shell
    let is_shell = shell_names.iter().any(|s| comm == s);
    if !is_shell {
        return  None;
    }

    // shells connectiong to loopback is not that suspicious
    if dest_ip.starts_with("127.") || dest_ip == "::1" {
        return None;
    }

    Some(Alert { pid: event_pid, 
        rule: "T1059 [Shell making outbound connection]", 
        detail: format!(
            "'{}' opened network connection to {}:{}",
            comm, dest_ip, dest_port
        ), 
        ancestry: ancestry.to_string(),
    })
}

pub fn check_suspicious_port(
    comm: &str,
    dest_ip: &str,
    dest_port: u16,
    event_pid: u32,
    ancestry: &str,
    suspicious_ports: &[u16],
) -> Option<Alert> {
    let is_suspicious_port = suspicious_ports.contains(&dest_port);
    if !is_suspicious_port {
        return None;
    }

    Some(Alert { pid: event_pid,
        rule: "T1071 [Connection to suspicious port]",
        detail: format!(
            "'{}' connected to {}:{} (known C2/reverse shell port)",
            comm, dest_ip, dest_port
        ),
        ancestry: ancestry.to_string(),
    })
}

pub fn check_obfuscated_command(
    comm: &str,
    cmdline: &str,
    event_pid: u32,
    ancestry: &str,
) -> Option<Alert> {
    let is_interpreter = [
        "bash", "sh", "zsh", "python", "python3",
        "perl", "ruby", "node", "php",
    ]
    .iter()
    .any(|s| comm.contains(s));

    if !is_interpreter {
        return None;
    }

    let matched = OBFUSCATED_PATTERNS
        .iter()
        .find(|pattern| cmdline.contains(**pattern));

    match matched {
        Some(pattern) => Some(Alert {
            pid: event_pid,
            rule: "T1027 [Obfuscated command execution]",
            detail: format!(
                "'{}' executed suspicious command pattern '{}': {}",
                comm, pattern, cmdline
            ),
            ancestry: ancestry.to_string(),
        }),
        None => None,
    }
}