// For detection rules
use std::{collections::HashMap, fmt::format};

// processes that are ALLOWED to spawn shells 
const SAFE_SHELL_PARENTS: &[&str] = &[
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

pub fn check_suspicious_shell_spawn(
    event_comm: &str,
    event_pid: u32,
    ppid: u32,
    ancestry: &str,
    tree: &std::collections::HashMap<u32, crate::ProcessNode>
) -> Option<Alert> {

    //check if the new process is shell
    let spawned_a_shell = SHELLS.iter().any(|s| event_comm == *s);
    if !spawned_a_shell {
        return None;
    }

    //we will look up parent now since we know the spawned process is a shell
    let parent_comm = match tree.get(&ppid) {
        Some(parent) => parent.comm.as_str(),
        // if there is no parent info then we will skip
        None => return None,
    };

    //check if parent is in our safe list
    let parent_is_safe = SAFE_SHELL_PARENTS.iter().any(|s| parent_comm.contains(s));
    if parent_is_safe {
        return None
    }

    // by the time we reach this part we know that there is something sus going on so we will fire alert
    // Honestly this might be a bad approach we will see tho
    Some(Alert { 
        pid: event_pid, 
        rule: "T1059 [Unexpected shell spawn]", 
        detail: format!("'{}' spawned a shell ({})", parent_comm, event_comm), 
        ancestry: ancestry.to_string() 
    })
}