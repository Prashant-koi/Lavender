use std::collections::HashMap;

use common::OpenEvent;

use crate::config::Config;
use crate::correlator::{BufferedEvent, Correlator, EventKind};
use crate::detection;
use crate::response::ResponseEngine;
use crate::runtime::{
    add_score_and_print_alert, ancestry_or_unknown, build_ancestry_chain, decode_c_string,
    parent_comm_for_pid, response_to_alert, ProcessNode,
};
use crate::scorer::Scorer;

pub fn handle_event(
    event: &OpenEvent,
    process_tree: &HashMap<u32, ProcessNode>,
    config: &Config,
    correlator: &mut Correlator,
    scorer: &mut Scorer,
    response_engine: &ResponseEngine,
) {
    let comm = decode_c_string(&event.comm);
    let filename = decode_c_string(&event.filename);

    let ancestry = build_ancestry_chain(event.pid, process_tree);
    let ancestry_for_event = ancestry_or_unknown(ancestry);
    let parent_comm = parent_comm_for_pid(event.pid, process_tree);

    // check
    let correlation_alert = correlator.push(
        event.pid,
        BufferedEvent {
            kind: EventKind::FileOpen,
            comm: comm.clone(),
            detail: filename.clone(),
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

    // do not print every file open that will flood the whole thing
    // so only run the detection and print if fires
    if let Some(alert) = detection::check_sensitive_file_read(
        &comm,
        &filename,
        event.pid,
        &ancestry_for_event,
        &config.filters.safe_file_readers,
        &config.filters.sensitive_files,
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
