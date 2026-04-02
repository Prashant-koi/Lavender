use std::collections::{HashMap, HashSet};

use crate::config::Config;
use crate::correlator::Correlator;
use crate::response::ResponseEngine;
use crate::scorer::Scorer;

pub mod ancestry;
pub mod alert_pipeline;

pub use ancestry::build_ancestry_chain;

#[derive(Clone, Debug)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub filename: String,
}

pub struct RuntimeState {
    pub process_tree: HashMap<u32, ProcessNode>,
    pub correlator: Correlator,
    pub scorer: Scorer,
    pub response_engine: ResponseEngine,
    pub seen_network_callers: HashSet<String>,
}

impl RuntimeState {
    pub fn new(config: &Config) -> Self {
        Self {
            process_tree: HashMap::new(),
            correlator: Correlator::from_filters(&config.filters),
            scorer: Scorer::new(),
            response_engine: ResponseEngine::from_config(&config.response),
            seen_network_callers: HashSet::new(),
        }
    }
}

// ppid resolve function
pub fn resolve_ppid(pid: u32, kernel_ppid: u32) -> u32 {
    if kernel_ppid != 0 {
        return kernel_ppid;
    }

    let status_path = format!("/proc/{}/status", pid);
    let contents = match std::fs::read_to_string(status_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().unwrap_or(0);
        }
    }

    0
}
