use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub filters: Filters,
} 

#[derive(Deserialize, Debug)]
pub struct Filters {
    pub safe_shell_launchers: Vec<String>,
    pub ignored_comms: Vec<String>,
    pub safe_file_readers: Vec<String>,
}

impl Config {
    pub fn load(path: &str) -> Self {
        if !Path::new(path).exists() {
            // if no config file then use defaults
            eprintln!("[lavender] no config found at {}, using defaults", path);
            return Self::default();
        }

        let contents = std::fs::read_to_string(path)
            .expect("could not read config file");

        toml::from_str(&contents)
            .expect("invalid TOML in config file")
    }

    fn default() -> Self {
        Config { 
            filters: Filters {
                safe_shell_launchers: vec![
                    "bash".into(), "sh".into(), "zsh".into(),
                    "fish".into(), "tmux".into(), "sshd".into(),
                    "sudo".into(), "su".into(), "login".into()
                ],
                ignored_comms: vec![],
                safe_file_readers: vec![],
            } 
        }
    }
}