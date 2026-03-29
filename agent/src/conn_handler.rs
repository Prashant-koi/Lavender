use std::collections::{HashMap, HashSet};

use common::ConnEvent;

use crate::config::Config;
use crate::correlator::{BufferedEvent, Correlator, EventKind};
use crate::detection;
use crate::output;
use crate::response::ResponseEngine;
use crate::runtime::{
    add_score_and_print_alert, ancestry_or_unknown, build_ancestry_chain, decode_c_string,
    parent_comm_for_pid, response_to_alert, ProcessNode,
};
use crate::scorer::{ScoreContext, Scorer};
use crate::users::UserDb;

pub fn handle_event(
    event: &ConnEvent,
    process_tree: &HashMap<u32, ProcessNode>,
    seen_network_callers: &mut HashSet<String>,
    user_db: &UserDb,
    config: &Config,
    correlator: &mut Correlator,
    scorer: &mut Scorer,
    response_engine: &ResponseEngine,
) {
    let comm = decode_c_string(&event.comm);

    //we will skip port 0 as they are internal socket operations
    if event.dport == 0 {
        return;
    }

    //if localhost also skip
    if event.af == 2 && event.daddr[0] == 127 {
        return;
    }

    let user = user_db.resolve(event.uid);
    let dest_ip = output::format_ip(event);

    let ancestry = build_ancestry_chain(event.pid, process_tree);
    let ancestry_for_event = ancestry_or_unknown(ancestry);
    let parent_comm = parent_comm_for_pid(event.pid, process_tree);

    //check the rules by pushing to correlator
    let correlation_alert = correlator.push(
        event.pid,
        BufferedEvent {
            kind: EventKind::Connect,
            comm: comm.clone(),
            detail: dest_ip.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ancestry: ancestry_for_event.clone(),
        },
    );

    if let Some(alert) = correlation_alert {
        add_score_and_print_alert(
            scorer,
            alert.pid,
            alert.rule,
            &alert.detail,
            &ancestry_for_event,
            parent_comm.as_deref(),
            Some(&comm),
        );

        let score = scorer.get_score(alert.pid);
        response_to_alert(response_engine, alert.pid, &comm, score);
    }

    output::print_conn(event, &comm, &user);

    //check if the connection is has been made for the first time
    if !seen_network_callers.contains(&comm) {
        seen_network_callers.insert(comm.clone());
        let first_net_detail = format!(
            "'{}' made its first observed outbound connection to {}:{}",
            comm, dest_ip, event.dport
        );
        //print this if it is the first time command has made an network connection
        output::print_alert(
            event.pid,
            "T1071 [First time Network Caller]",
            &first_net_detail,
            &ancestry_for_event,
        );

        // We score this event even if it does not cross warning threshold,
        // so later high-confidence rules can aggregate faster.
        let first_net_ctx = ScoreContext {
            ancestry: &ancestry_for_event,
            parent_comm: parent_comm.as_deref(),
            child_comm: Some(&comm),
            is_sequence_match: false,
        };
        let _ = scorer.add_score_for_rule_with_context(
            event.pid,
            "T1071 [First time Network Caller]",
            &first_net_ctx,
        );
    }

    // Rule 1, there is high confidence of suspicious network connection
    if let Some(alert) = detection::check_shell_network_connection(
        &comm,
        &dest_ip,
        event.dport,
        event.pid,
        &ancestry_for_event,
        &config.filters.shell_names,
    ) {
        add_score_and_print_alert(
            scorer,
            alert.pid,
            alert.rule,
            &alert.detail,
            &ancestry_for_event,
            parent_comm.as_deref(),
            Some(&comm),
        );

        let score = scorer.get_score(alert.pid);
        response_to_alert(response_engine, alert.pid, &comm, score);
    }

    // Rule 2, there is a midium level of confidence in this case
    if let Some(alert) = detection::check_suspicious_port(
        &comm,
        &dest_ip,
        event.dport,
        event.pid,
        &ancestry_for_event,
        &config.filters.suspicious_ports,
    ) {
        add_score_and_print_alert(
            scorer,
            alert.pid,
            alert.rule,
            &alert.detail,
            &ancestry_for_event,
            parent_comm.as_deref(),
            Some(&comm),
        );

        let score = scorer.get_score(alert.pid);
        response_to_alert(response_engine, alert.pid, &comm, score);
    }
}
