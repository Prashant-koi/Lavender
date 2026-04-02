use crate::correlator::BufferedEvent;
use crate::output;
use crate::response::{ResponseAction, SkipReason};
use crate::scorer::ScoreContext;

use super::RuntimeState;

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

// making a function of this because we have been doing this alot
pub fn add_score_and_print_alert(
    scorer: &mut crate::scorer::Scorer,
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
    response_engine: &crate::response::ResponseEngine,
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
