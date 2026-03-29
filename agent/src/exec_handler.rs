use common::ExecEvent;

use crate::config::Config;
use crate::correlator::{BufferedEvent, EventKind};
use crate::detection;
use crate::output;
use crate::runtime::{
    add_score_and_print_alert, basename, build_ancestry_chain, decode_c_string, parent_comm_for_pid,
    resolve_ppid, response_to_alert, RuntimeState,
};
use crate::users::UserDb;

pub fn handle_event(
    event: &ExecEvent,
    state: &mut RuntimeState,
    user_db: &UserDb,
    config: &Config,
) {
    // eBPF sends fixed-size null-terminated byte arrays.
    // Convert to UTF-8 strings and strip trailing null bytes.
    let comm = decode_c_string(&event.comm);
    let filename = decode_c_string(&event.filename);

    let argv1 = decode_c_string(&event.argv1);
    let argv2 = decode_c_string(&event.argv2);

    let cmdline = if argv1.is_empty() {
        filename.clone()
    } else if argv2.is_empty() {
        format!("{} {}", filename, argv1)
    } else {
        format!("{} {} {}", filename, argv1, argv2)
    };

    let ppid = resolve_ppid(event.pid, event.ppid);
    let user = user_db.resolve(event.uid);

    // we will keep latest process metadata so we can reconstruct lineage
    state.process_tree.insert(
        event.pid,
        crate::runtime::ProcessNode {
            pid: event.pid,
            ppid,
            comm: comm.to_string(),
            filename: filename.to_string(),
        },
    );

    let ancestry = build_ancestry_chain(event.pid, &state.process_tree);
    let parent_comm = parent_comm_for_pid(event.pid, &state.process_tree);
    let exec_target = basename(&filename).to_string();

    // inser to the correlator and check
    let correlation_alert = state.correlator.push(
        event.pid,
        BufferedEvent {
            kind: EventKind::Exec,
            comm: comm.clone(),
            detail: filename.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ancestry: ancestry.clone(),
        },
    );

    if let Some(alert) = correlation_alert {
        add_score_and_print_alert(
            &mut state.scorer,
            alert.pid,
            alert.rule,
            &alert.detail,
            &ancestry,
            parent_comm.as_deref(),
            Some(&exec_target),
        );

        let score = state.scorer.get_score(alert.pid);
        response_to_alert(&state.response_engine, alert.pid, &comm, score);
    }

    //we will skip the ignored processes(those mentioned in the lavender.toml)
    if config
        .filters
        .ignored_comms
        .iter()
        .any(|s| comm.contains(s.as_str()))
    {
        return;
    }

    output::print_exec(event.pid, ppid, &user, &comm, &filename, &cmdline, &ancestry);

    //checking if the spawned process has a suspicious parent or is supicious refer detection.rs
    if let Some(alert) = detection::check_suspicious_shell_spawn(
        parent_comm.as_deref().unwrap_or(""),
        &filename,
        event.pid,
        &ancestry,
        &config.filters.safe_shell_launchers,
        &config.filters.shell_names,
    ) {
        add_score_and_print_alert(
            &mut state.scorer,
            alert.pid,
            alert.rule,
            &alert.detail,
            &ancestry,
            parent_comm.as_deref(),
            Some(&exec_target),
        );

        let score = state.scorer.get_score(alert.pid);
        response_to_alert(&state.response_engine, alert.pid, &comm, score);
    }

    // obfuscated one-liners and fetch-and-exec patterns are high-signal for abuse
    if let Some(alert) = detection::check_obfuscated_command(&comm, &cmdline, event.pid, &ancestry) {
        add_score_and_print_alert(
            &mut state.scorer,
            alert.pid,
            alert.rule,
            &alert.detail,
            &ancestry,
            parent_comm.as_deref(),
            Some(&exec_target),
        );

        let score = state.scorer.get_score(alert.pid);
        response_to_alert(&state.response_engine, alert.pid, &comm, score);
    }
}
