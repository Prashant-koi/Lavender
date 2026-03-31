use common::ConnEvent;

use crate::config::Config;
use crate::correlator::BufferedEvent;
use crate::detection;
use crate::output;
use crate::runtime::{
    AlertContext,
    ancestry_or_unknown, build_ancestry_chain, decode_c_string, parent_comm_for_pid,
    maybe_respond, push_correlator_and_process_alert, record_alert, RuntimeState,
};
use crate::users::UserDb;

/// Handles one network-connect event from the eBPF ring buffer.
///
/// Responsibilities:
/// - apply basic noise filters (port 0 and localhost IPv4)
/// - decode/format connection details and ancestry context
/// - feed connect activity into correlator chain detection
/// - track first-seen network callers
/// - run network-focused rules and alert/response pipeline
pub fn handle_event(
    event: &ConnEvent,
    state: &mut RuntimeState,
    user_db: &UserDb,
    config: &Config,
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

    let ancestry = build_ancestry_chain(event.pid, &state.process_tree);
    let ancestry_for_event = ancestry_or_unknown(ancestry);
    let parent_comm = parent_comm_for_pid(event.pid, &state.process_tree);
    let alert_context = AlertContext::new(
        event.pid,
        &ancestry_for_event,
        parent_comm.as_deref(),
        Some(&comm),
        &comm,
    );

    // push to correlator and run the shared alert pipeline for chain alerts
    push_correlator_and_process_alert(
        state,
        &alert_context,
        BufferedEvent::connect(comm.clone(), dest_ip.clone(), ancestry_for_event.clone()),
    );

    output::print_conn(event, &comm, &user);

    //check if the connection is has been made for the first time
    if !state.seen_network_callers.contains(&comm) {
        state.seen_network_callers.insert(comm.clone());
        let first_net_detail = format!(
            "'{}' made its first observed outbound connection to {}:{}",
            comm, dest_ip, event.dport
        );
        record_alert(
            state,
            &alert_context,
            "T1071 [First time Network Caller]",
            &first_net_detail,
        );
        maybe_respond(state, &alert_context);
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
        record_alert(
            state,
            &alert_context,
            alert.rule,
            &alert.detail,
        );
        maybe_respond(state, &alert_context);
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
        record_alert(
            state,
            &alert_context,
            alert.rule,
            &alert.detail,
        );
        maybe_respond(state, &alert_context);
    }
}
