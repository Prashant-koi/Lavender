use super::{BufferedEvent, CorrelationAlert, Correlator, EventKind};

// strict order: execve(bash) -> connect(external) -> execve(sh)
// this is stronger than just checking shell + network happened sometime in the buffer
pub(super) fn reverse_shell_rule(
    pid: u32,
    related_events: &[BufferedEvent],
) -> Option<CorrelationAlert> {
    for i in 0..related_events.len() {
        let first = &related_events[i];
        if !Correlator::is_exec_target(first, "bash") {
            continue;
        }

        for j in (i + 1)..related_events.len() {
            let second = &related_events[j];
            if !Correlator::is_external_connect(second) {
                continue;
            }

            for k in (j + 1)..related_events.len() {
                let third = &related_events[k];
                if !Correlator::is_exec_target(third, "sh") {
                    continue;
                }

                return Some(CorrelationAlert {
                    pid,
                    rule: "CHAIN Reverse shell behaviour",
                    detail: format!(
                        "ordered reverse-shell chain matched: execve(bash) -> connect(external) -> execve(sh)"
                    ),
                });
            }
        }
    }

    None
}

// we will try to find the pattern of opening a sensitive file and then executing something
pub(super) fn cred_exec_rule(
    correlator: &Correlator,
    pid: u32,
    related_events: &[BufferedEvent],
) -> Option<CorrelationAlert> {
    let read_sensitive = related_events.iter().any(|e|
        e.kind == EventKind::FileOpen &&
        correlator.sensitive_file_patterns
            .iter()
            .any(|s| e.detail.contains(s.as_str()))
    );

    if !read_sensitive {
        return None;
    }

    let kinds: Vec<&EventKind> = related_events.iter().map(|e| &e.kind).collect();
    let exec_after = kinds.windows(2).any(|w|
        w[0] == &EventKind::FileOpen &&
        w[1] == &EventKind::Exec
    );

    if !exec_after {
        return None;
    }

    Some(CorrelationAlert {
        pid,
        rule: "CHAIN Credential access then execution",
        detail: format!(
            "process read sensitive file then executed a new process"
        ),
    })
}

// the pattern it checks is 5+ exec events in less than 10 seconds
pub(super) fn rapid_spawn_rule(
    correlator: &Correlator,
    pid: u32,
    current_event: &BufferedEvent,
    related_events: &[BufferedEvent],
) -> Option<CorrelationAlert> {
    // only evaluate this rule when the current event itself is exec so we don't keep re-firing on open/connect events
    if current_event.kind != EventKind::Exec {
        return None;
    }

    // if the current chain ancestry is noisy (e.g. code), skip this rapid rule entirely
    if Correlator::ancestry_has_noisy_comm(&current_event.ancestry, &correlator.noisy_comms) {
        return None;
    }

    // exclude noisy comms from the rapid-spawn calculation to avoid editor/tooling burst false positives
    let exec_events: Vec<&BufferedEvent> = related_events
        .iter()
        .filter(|e| e.kind == EventKind::Exec)
        .filter(|e| !correlator.is_noisy_comm(&e.comm))
        .collect();

    let exec_count = exec_events.len();
    if exec_count < 5 {
        return None;
    }

    let oldest_exec = exec_events.first().map(|e| e.timestamp).unwrap_or(0);
    let newest_exec = exec_events.last().map(|e| e.timestamp).unwrap_or(0);

    // all 5 or more within 10 secs
    if newest_exec - oldest_exec < 10 {
        return Some(CorrelationAlert {
            pid,
            rule: "CHAIN Rapid process spawning",
            detail: format!("{} processes spawned within 10 seconds", exec_count),
        });
    }

    None
}
