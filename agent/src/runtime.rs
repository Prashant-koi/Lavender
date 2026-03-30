use std::collections::{HashMap, HashSet};

use crate::config::Config;
use crate::correlator::{BufferedEvent, Correlator};
use crate::output;
use crate::response::{ResponseAction, ResponseEngine, SkipReason};
use crate::scorer::{ScoreContext, Scorer};

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

#[derive(Clone, Copy, Debug)]
pub struct AlertContext<'a> {
    pub pid: u32,
    pub ancestry: &'a str,
    pub parent_comm: Option<&'a str>,
    pub child_comm: Option<&'a str>,
    pub response_comm: &'a str,
}

impl<'a> AlertContext<'a> {
    pub fn new(
        pid: u32,
        ancestry: &'a str,
        parent_comm: Option<&'a str>,
        child_comm: Option<&'a str>,
        response_comm: &'a str,
    ) -> Self {
        Self {
            pid,
            ancestry,
            parent_comm,
            child_comm,
            response_comm,
        }
    }
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

pub fn build_ancestry_chain(pid: u32, tree: &HashMap<u32, ProcessNode>) -> String {
    let mut chain = vec![];
    let mut current_pid = pid;

    //we will walk upward through parents and go max of 8 levels
    // max limit to stop inf loops in case the data is weird
    for _ in 0..8 {
        match tree.get(&current_pid) {
            Some(node) => {
                chain.push(node.comm.clone());
                if node.ppid == 0 || node.ppid == current_pid {
                    //either we reached init or a cycle
                    break;
                }
                current_pid = node.ppid;
            }
            None => break,
        }
    }

    // reverse the chian since we built it button up
    chain.reverse();
    chain.join("=>")
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

pub fn decode_c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn parent_comm_for_pid(pid: u32, tree: &HashMap<u32, ProcessNode>) -> Option<String> {
    let node = tree.get(&pid)?;
    let parent = tree.get(&node.ppid)?;
    Some(parent.comm.clone())
}

pub fn ancestry_or_unknown(ancestry: String) -> String {
    if ancestry.is_empty() {
        "unknown".to_string()
    } else {
        ancestry
    }
}

// making a function of this because we have been doing this alot
pub fn add_score_and_print_alert(
    scorer: &mut Scorer,
    pid: u32,
    rule: &'static str,
    detail: &str,
    ancestry: &str,
    parent_comm: Option<&str>,
    child_comm: Option<&str>,
) {
    let score_ctx = ScoreContext {
        ancestry,
        parent_comm,
        child_comm,
        is_sequence_match: rule.starts_with("CHAIN "),
    };

    if let Some((score, severity, breakdown)) = scorer.add_score_for_rule_with_context(pid, rule, &score_ctx) {
        output::print_scored_alert(
            pid,
            rule,
            detail,
            ancestry,
            score,
            severity.label(),
            Some(breakdown.base),
            Some(breakdown.lineage_bonus),
            Some(breakdown.rarity_bonus),
            Some(breakdown.sequence_bonus),
        );
    }
}

pub fn response_to_alert(
    response_engine: &ResponseEngine,
    pid: u32,
    comm: &str,
    score: u32,
) {
    match response_engine.evaluate(pid, comm, score) {
        ResponseAction::Kill { pid, comm, score } => {
            output::print_kill(pid, &comm, score, false);
        }
        ResponseAction::Skipped { pid, comm, reason } => {
            match reason {
                SkipReason::DryRun => {
                    output::print_kill(pid, &comm, score, true);
                }
                SkipReason::Protected => {
                    eprintln!("[response] skipped kill of protected process '{}' (pid {})", comm, pid);
                }
                SkipReason::BelowThreshold => {
                    // silent - below threshold is normal, don't spam
                }
                SkipReason::KillFailed => {
                    eprintln!("[response] failed to kill process '{}' (pid {})", comm, pid);
                }
            }
        }
    }
}

/// we will record alert details by scoring and printing when threshold is reached.
pub fn record_alert(
    state: &mut RuntimeState,
    context: &AlertContext<'_>,
    rule: &'static str,
    detail: &str,
) {
    add_score_and_print_alert(
        &mut state.scorer,
        context.pid,
        rule,
        detail,
        context.ancestry,
        context.parent_comm,
        context.child_comm,
    );
}

/// we will evaluate and run the configured response using latest score for this pid.
pub fn maybe_respond(
    state: &RuntimeState,
    context: &AlertContext<'_>,
) {
    let score = state.scorer.get_score(context.pid);
    response_to_alert(&state.response_engine, context.pid, context.response_comm, score);
}

/// we will push into correlator and if sequence rule matches then record + maybe respond.
pub fn push_correlator_and_process_alert(
    state: &mut RuntimeState,
    context: &AlertContext<'_>,
    event: BufferedEvent,
) {
    if let Some(alert) = state.correlator.push(context.pid, event) {
        let correlation_context = AlertContext {
            pid: alert.pid,
            ..*context
        };
        record_alert(
            state,
            &correlation_context,
            alert.rule,
            &alert.detail,
        );
        maybe_respond(state, &correlation_context);
    }
}
