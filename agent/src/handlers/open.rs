use common::OpenEvent;

use crate::config::Config;
use crate::correlator::BufferedEvent;
use crate::detection;
use crate::handlers::decode_c_string;
use crate::runtime::alert_pipeline::{
    AlertContext, maybe_respond, push_correlator_and_process_alert, record_alert,
};
use crate::runtime::ancestry::{ancestry_or_unknown, build_ancestry_chain, parent_comm_for_pid};
use crate::runtime::RuntimeState;

/// Handles one file-open event from the eBPF ring buffer.
///
/// Responsibilities:
/// - decode open payload fields (`comm`, `filename`)
/// - build ancestry context for scoring and correlation
/// - feed file-open activity into correlator chain detection
/// - run sensitive-file-read detection and alert pipeline
pub fn handle_event(
    event: &OpenEvent,
    state: &mut RuntimeState,
    config: &Config,
) {
    let comm = decode_c_string(&event.comm);
    let filename = decode_c_string(&event.filename);

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

    // push to correlator and run shared alert pipeline if a chain rule matched
    push_correlator_and_process_alert(
        state,
        &alert_context,
        BufferedEvent::file_open(comm.clone(), filename.clone(), ancestry_for_event.clone()),
    );

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
        record_alert(
            state,
            &alert_context,
            alert.rule,
            &alert.detail,
        );
        maybe_respond(state, &alert_context);
    }
}
