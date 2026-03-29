use agent::config::Filters;
use agent::correlator::{BufferedEvent, Correlator, EventKind};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn test_filters(max_events: usize, max_age_secs: u64) -> Filters {
    Filters {
        safe_shell_launchers: vec![],
        ignored_comms: vec![],
        safe_file_readers: vec![],
        shell_names: vec!["bash".into(), "sh".into(), "zsh".into()],
        sensitive_files: vec!["/etc/shadow".into()],
        suspicious_ports: vec![4444],
        noisy_comms: vec![],
        correlator_max_events: max_events,
        correlator_max_age_secs: max_age_secs,
    }
}

fn evt(kind: EventKind, comm: &str, detail: &str, ts: u64, ancestry: &str) -> BufferedEvent {
    BufferedEvent {
        kind,
        comm: comm.to_string(),
        detail: detail.to_string(),
        timestamp: ts,
        ancestry: ancestry.to_string(),
    }
}

// Verifies the reverse-shell sequence triggers when events arrive in the expected order.
#[test]
fn reverse_shell_chain_triggers_in_order() {
    let mut c = Correlator::from_filters(&test_filters(20, 30));
    let t = now_secs();

    assert!(c.push(10, evt(EventKind::Exec, "bash", "/usr/bin/bash", t, "zsh=>bash")).is_none());
    assert!(c.push(10, evt(EventKind::Connect, "bash", "1.1.1.1", t + 1, "zsh=>bash")).is_none());

    let alert = c.push(
        10,
        evt(EventKind::Exec, "bash", "/usr/bin/sh", t + 2, "zsh=>bash"),
    );
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "CHAIN Reverse shell behaviour");
}

// Ensures the reverse-shell sequence does not trigger when the event order is wrong.
#[test]
fn reverse_shell_chain_does_not_trigger_wrong_order() {
    let mut c = Correlator::from_filters(&test_filters(20, 30));
    let t = now_secs();

    assert!(c.push(11, evt(EventKind::Exec, "bash", "/usr/bin/sh", t, "zsh=>bash")).is_none());
    assert!(c.push(11, evt(EventKind::Connect, "bash", "1.1.1.1", t + 1, "zsh=>bash")).is_none());
    assert!(c.push(11, evt(EventKind::Exec, "bash", "/usr/bin/bash", t + 2, "zsh=>bash")).is_none());
}

// Confirms credential access followed by execution raises the corresponding chain alert.
#[test]
fn credential_access_then_exec_triggers() {
    let mut c = Correlator::from_filters(&test_filters(20, 30));
    let t = now_secs();

    assert!(c.push(12, evt(EventKind::FileOpen, "cat", "/etc/shadow", t, "zsh=>cat")).is_none());
    let alert = c.push(
        12,
        evt(EventKind::Exec, "cat", "/usr/bin/id", t + 1, "zsh=>cat"),
    );

    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "CHAIN Credential access then execution");
}

// Checks that rapid consecutive exec events trigger the rapid-spawn correlation rule.
#[test]
fn rapid_spawn_triggers_on_fifth_exec() {
    let mut c = Correlator::from_filters(&test_filters(20, 30));
    let t = now_secs();

    assert!(c.push(13, evt(EventKind::Exec, "python", "/usr/bin/python", t, "zsh=>python")).is_none());
    assert!(c.push(13, evt(EventKind::Exec, "python", "/usr/bin/python", t + 1, "zsh=>python")).is_none());
    assert!(c.push(13, evt(EventKind::Exec, "python", "/usr/bin/python", t + 2, "zsh=>python")).is_none());
    assert!(c.push(13, evt(EventKind::Exec, "python", "/usr/bin/python", t + 3, "zsh=>python")).is_none());

    let alert = c.push(
        13,
        evt(
            EventKind::Exec,
            "python",
            "/usr/bin/python",
            t + 4,
            "zsh=>python",
        ),
    );
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "CHAIN Rapid process spawning");
}

// Verifies a small per-pid buffer can evict early events and prevent full sequence matching.
#[test]
fn small_buffer_can_prevent_longer_sequence_build_up() {
    let mut c = Correlator::from_filters(&test_filters(2, 30));
    let t = now_secs();

    assert!(c.push(14, evt(EventKind::Exec, "bash", "/usr/bin/bash", t, "zsh=>bash")).is_none());
    assert!(c.push(14, evt(EventKind::Connect, "bash", "1.1.1.1", t + 1, "zsh=>bash")).is_none());

    // with max_events=2 the first event is evicted before this arrives
    let alert = c.push(
        14,
        evt(EventKind::Exec, "bash", "/usr/bin/sh", t + 2, "zsh=>bash"),
    );
    assert!(alert.is_none());
}

// Ensures future-dated events do not cause eviction-time arithmetic panics.
#[test]
fn future_timestamp_does_not_panic_during_eviction() {
    let mut c = Correlator::from_filters(&test_filters(20, 30));
    let t = now_secs();

    assert!(c.push(15, evt(EventKind::Exec, "bash", "/usr/bin/bash", t + 300, "zsh=>bash")).is_none());
    assert!(c.push(15, evt(EventKind::Exec, "bash", "/usr/bin/bash", t, "zsh=>bash")).is_none());
}

// Verifies related ancestry chains can correlate sequence events across different PIDs.
#[test]
fn reverse_shell_chain_can_correlate_across_related_ancestry_pids() {
    let mut c = Correlator::from_filters(&test_filters(20, 30));
    let t = now_secs();

    assert!(c.push(20, evt(EventKind::Exec, "bash", "/usr/bin/bash", t, "python=>bash")).is_none());
    assert!(c.push(21, evt(EventKind::Connect, "bash", "1.1.1.1", t + 1, "python=>bash=>curl")).is_none());

    let alert = c.push(
        22,
        evt(
            EventKind::Exec,
            "bash",
            "/usr/bin/sh",
            t + 2,
            "python=>bash=>curl=>sh",
        ),
    );
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "CHAIN Reverse shell behaviour");
}
