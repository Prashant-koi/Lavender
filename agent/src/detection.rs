// For detection rules

// processes that are ALLOWED to spawn shells 
const SAFE_SHELL_LAUNCHERS: &[&str] = &[
    "bash", "sh", "zsh", "fish",        // shells spawning subshells
    "tmux", "tmux: server",              // terminal multiplexers  
    "alacritty", "kitty", "gnome-term",  // terminal emulators
    "sshd",                              // remote login
    "sudo", "su",                        // privilege escalation
    "login",                             // login process
];

//what counts as a shell being spawned
const SHELLS: &[&str] = &["bash", "sh", "zsh", "fish", "dash"];

pub struct Alert {
    pub pid: u32,
    pub rule: &'static str,
    pub detail: String,
    pub ancestry: String,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn check_suspicious_shell_spawn(
    launcher_comm: &str,
    target_filename: &str,
    event_pid: u32,
    ancestry: &str,
) -> Option<Alert> {
    let target_base = basename(target_filename);

    //check if the new process is shell
    let target_is_shell = SHELLS.iter().any(|s| target_base == *s);
    if !target_is_shell {
        return None
    }

    //allow known normal launchers
    let laucher_is_safe = SAFE_SHELL_LAUNCHERS.iter().any(|s| launcher_comm.contains(s));
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