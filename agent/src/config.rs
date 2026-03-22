use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug)]
pub struct Config {
    pub filters: Filters,
    pub response: ResponseConfig,
} 

#[derive(Deserialize, Debug)]
pub struct Filters {
    pub safe_shell_launchers: Vec<String>,
    pub ignored_comms: Vec<String>,
    pub safe_file_readers: Vec<String>,
    #[serde(default = "default_shell_names")]
    pub shell_names: Vec<String>,
    #[serde(default = "default_sensitive_files")]
    pub sensitive_files: Vec<String>,
    #[serde(default = "default_suspicious_ports")]
    pub suspicious_ports: Vec<u16>,
    #[serde(default = "default_noisy_comms")]
    pub noisy_comms: Vec<String>,
    #[serde(default = "default_correlator_max_events")]
    pub correlator_max_events: usize,
    #[serde(default = "default_correlator_max_age_secs")]
    pub correlator_max_age_secs: u64,
}

#[derive(Deserialize, Debug)]
pub struct ResponseConfig {
    pub dry_run: bool,
    pub kill_threshold: u32,
    pub protected_comms: Vec<String>,
}

fn default_shell_names() -> Vec<String> {
    vec![
        "bash".into(), "sh".into(), "zsh".into(), "fish".into(), "dash".into(),
    ]
}

fn default_sensitive_files() -> Vec<String> {
    vec![
        "/etc/shadow".into(),
        "/etc/passwd".into(),
        "/etc/sudoers".into(),
        "/etc/sudoers.d".into(),
        "/.ssh/id_rsa".into(),
        "/.ssh/id_ed25519".into(),
        "/.ssh/authorized_keys".into(),
        "/.bash_history".into(),
        "/.zsh_history".into(),
        "/root/.ssh".into(),
    ]
}

fn default_suspicious_ports() -> Vec<u16> {
    vec![4444, 1337, 9001, 9999, 6666, 31337, 5555]
}

fn default_noisy_comms() -> Vec<String> {
    vec![
        "code".into(), "cpuUsage".into(), "cargo".into(), "rustc".into(), "make".into(),
    ]
}

fn default_correlator_max_events() -> usize {
    20
}

fn default_correlator_max_age_secs() -> u64 {
    30
}

impl Config {
    pub fn load_auto() -> Self {
        if let Ok(path) = std::env::var("LAVENDER_CONFIG") {
            let candidate = PathBuf::from(path);
            if candidate.exists() {
                return Self::load_from_path(&candidate);
            }
        }

        if let Some(path) = Self::find_in_ancestor_dirs("lavender.toml") {
            return Self::load_from_path(&path);
        }

        eprintln!("[lavender] no config found, using defaults");
        Self::default()
    }

    pub fn load(path: &str) -> Self {
        let path_ref = Path::new(path);
        if !path_ref.exists() {
            // if no config file then use defaults
            eprintln!("[lavender] no config found at {}, using defaults", path);
            return Self::default();
        }

        Self::load_from_path(path_ref)
    }

    fn load_from_path(path: &Path) -> Self {
        let contents = std::fs::read_to_string(path)
            .expect("could not read config file");

        toml::from_str(&contents)
            .expect("invalid TOML in config file")
    }

    fn find_in_ancestor_dirs(file_name: &str) -> Option<PathBuf> {
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(path) = Self::search_upwards(cwd, file_name) {
                return Some(path);
            }
        }

        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                if let Some(path) = Self::search_upwards(exe_dir.to_path_buf(), file_name) {
                    return Some(path);
                }
            }
        }

        None
    }

    fn search_upwards(start: PathBuf, file_name: &str) -> Option<PathBuf> {
        for dir in start.ancestors() {
            let candidate = dir.join(file_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }

        None
    }

    fn default() -> Self {
        Config { 
            filters: Filters {
                safe_shell_launchers: vec![
                    "tmux".into(), "alacritty".into(), "kitty".into(),
                    "sshd".into(), "sudo".into(), "su".into(),
                    "login".into(), "Hyprland".into(), "code".into()
                ],
                ignored_comms: vec![],
                safe_file_readers: vec![
                    "sshd".into(), "sudo".into(), "passwd".into(), "shadow".into(),
                    "pam".into(), "bash".into(), "zsh".into(), "sh".into(),
                ],
                shell_names: default_shell_names(),
                sensitive_files: default_sensitive_files(),
                suspicious_ports: default_suspicious_ports(),
                noisy_comms: default_noisy_comms(),
                correlator_max_events: default_correlator_max_events(),
                correlator_max_age_secs: default_correlator_max_age_secs(),
            } ,
            response: ResponseConfig {
                dry_run: true,
                kill_threshold: 200, 
                protected_comms: vec![
                    "systemd".into(),"sshd".into(),
                    "sudo".into(), "init".into(),
                ],
            }
        }
    }
}