use agent::config::{AgentConfig, Config, Filters, ResponseConfig};
use agent::conn_handler;
use agent::correlator::{BufferedEvent, EventKind};
use agent::exec_handler;
use agent::exit_handler;
use agent::runtime::{build_ancestry_chain, ProcessNode, RuntimeState};
use agent::users::UserDb;
use common::{ConnEvent, ExecEvent};

fn default_config() -> Config {
    Config {
        agent: AgentConfig {
            agent_id: "test-agent-1".into(),
        },
        filters: Filters {
            safe_shell_launchers: vec!["code".into(), "tmux".into()],
            ignored_comms: vec![],
            safe_file_readers: vec!["sudo".into(), "sshd".into()],
            shell_names: vec!["bash".into(), "sh".into(), "zsh".into()],
            sensitive_files: vec!["/etc/shadow".into(), "/etc/passwd".into()],
            suspicious_ports: vec![4444, 1337],
            noisy_comms: vec!["code".into()],
            correlator_max_events: 20,
            correlator_max_age_secs: 30,
        },
        response: ResponseConfig {
            dry_run: true,
            kill_threshold: 200,
            protected_comms: vec!["systemd".into(), "sshd".into(), "sudo".into()],
        },
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn c_array<const N: usize>(value: &str) -> [u8; N] {
    let mut buf = [0u8; N];
    let bytes = value.as_bytes();
    let len = bytes.len().min(N.saturating_sub(1));
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

fn exec_event(pid: u32, ppid: u32, comm: &str, filename: &str) -> ExecEvent {
    ExecEvent {
        pid,
        ppid,
        uid: 0,
        comm: c_array(comm),
        filename: c_array(filename),
        argv1: [0; 128],
        argv2: [0; 128],
    }
}

fn conn_event(pid: u32, comm: &str, ip: [u8; 4], port: u16) -> ConnEvent {
    let mut daddr = [0u8; 16];
    daddr[..4].copy_from_slice(&ip);

    ConnEvent {
        pid,
        uid: 0,
        comm: c_array(comm),
        daddr,
        dport: port,
        af: 2,
    }
}

// Verifies ancestry chain reconstruction includes parent-to-child order correctly.
#[test]
fn ancestry_chain_resolves_correctly() {
    let mut state = RuntimeState::new(&default_config());

    // simulate: zsh (pid 100) spawned bash (pid 200)
    state.process_tree.insert(
        100,
        ProcessNode {
            pid: 100,
            ppid: 1,
            comm: "zsh".into(),
            filename: "/usr/bin/zsh".into(),
        },
    );
    state.process_tree.insert(
        200,
        ProcessNode {
            pid: 200,
            ppid: 100,
            comm: "bash".into(),
            filename: "/usr/bin/bash".into(),
        },
    );

    let chain = build_ancestry_chain(200, &state.process_tree);
    assert_eq!(chain, "zsh=>bash");
}

// Ensures ancestry reconstruction stops cleanly when parent metadata is unavailable.
#[test]
fn ancestry_chain_stops_at_missing_parent() {
    let mut state = RuntimeState::new(&default_config());

    // bash exists but its parent (zsh) is not in the tree
    // this simulates processes that were running before Lavender started
    state.process_tree.insert(
        200,
        ProcessNode {
            pid: 200,
            ppid: 100,
            comm: "bash".into(),
            filename: "/usr/bin/bash".into(),
        },
    );

    let chain = build_ancestry_chain(200, &state.process_tree);
    assert_eq!(chain, "bash");
}

// Confirms ancestry traversal handles parent-cycle data without infinite loops.
#[test]
fn ancestry_chain_handles_cycle_gracefully() {
    let mut state = RuntimeState::new(&default_config());

    // pathological case: process is its own parent
    state.process_tree.insert(
        100,
        ProcessNode {
            pid: 100,
            ppid: 100,
            comm: "weird".into(),
            filename: "/bin/weird".into(),
        },
    );

    // should not infinite loop — the cycle check should break
    let chain = build_ancestry_chain(100, &state.process_tree);
    assert_eq!(chain, "weird");
}

// Verifies process-exit handling removes process state from tree, scorer, and correlator.
#[test]
fn process_exit_cleans_up_tree_scorer_and_correlator() {
    let mut state = RuntimeState::new(&default_config());
    let t = now_secs();

    // set up a process with score and correlation history
    state.process_tree.insert(
        999,
        ProcessNode {
            pid: 999,
            ppid: 1,
            comm: "bash".into(),
            filename: "/bin/bash".into(),
        },
    );
    let _ = state
        .scorer
        .add_score(999, "T1059 [Unexpected shell spawn]", 40);

    let _ = state.correlator.push(
        999,
        BufferedEvent {
            kind: EventKind::Exec,
            comm: "bash".into(),
            detail: "/usr/bin/bash".into(),
            timestamp: t,
            ancestry: "zsh=>bash".into(),
        },
    );
    let _ = state.correlator.push(
        999,
        BufferedEvent {
            kind: EventKind::Connect,
            comm: "bash".into(),
            detail: "1.1.1.1".into(),
            timestamp: t + 1,
            ancestry: "zsh=>bash".into(),
        },
    );

    exit_handler::handle_event(999, &mut state);

    // verify tree and score are gone
    assert!(state.process_tree.get(&999).is_none());
    assert_eq!(state.scorer.get_score(999), 0);

    // if correlator cleanup failed, this final step could trigger old reverse-shell state
    let post_exit = state.correlator.push(
        999,
        BufferedEvent {
            kind: EventKind::Exec,
            comm: "bash".into(),
            detail: "/usr/bin/sh".into(),
            timestamp: t + 2,
            ancestry: "zsh=>bash".into(),
        },
    );
    assert!(post_exit.is_none());
}

// Checks exec handling records enough context for shell-spawn scoring behavior.
#[test]
fn exec_handler_uses_parent_comm_for_shell_spawn_detection() {
    let config = default_config();
    let mut state = RuntimeState::new(&config);
    let user_db = UserDb::load();

    exec_handler::handle_event(
        &exec_event(100, 1, "curl", "/usr/bin/curl"),
        &mut state,
        &user_db,
        &config,
    );
    exec_handler::handle_event(
        &exec_event(101, 100, "sh", "/bin/sh"),
        &mut state,
        &user_db,
        &config,
    );

    assert_eq!(build_ancestry_chain(101, &state.process_tree), "curl=>sh");
    assert!(state.scorer.get_score(101) > 0);
}

// Ensures first-time network caller scoring is applied once for repeated connections.
#[test]
fn first_time_network_caller_is_scored_once_via_conn_handler() {
    let config = default_config();
    let mut state = RuntimeState::new(&config);
    let user_db = UserDb::load();

    state.process_tree.insert(
        100,
        ProcessNode {
            pid: 100,
            ppid: 1,
            comm: "bash".into(),
            filename: "/bin/bash".into(),
        },
    );
    state.process_tree.insert(
        101,
        ProcessNode {
            pid: 101,
            ppid: 100,
            comm: "curl".into(),
            filename: "/usr/bin/curl".into(),
        },
    );

    let event = conn_event(101, "curl", [1, 1, 1, 1], 80);
    conn_handler::handle_event(&event, &mut state, &user_db, &config);
    let first_score = state.scorer.get_score(101);

    conn_handler::handle_event(&event, &mut state, &user_db, &config);

    assert!(state.seen_network_callers.contains("curl"));
    assert!(first_score > 0);
    assert_eq!(state.scorer.get_score(101), first_score);
}

// Verifies localhost and port-zero connection events are filtered before first-time tracking.
#[test]
fn conn_handler_filters_localhost_and_port_zero_before_first_time_tracking() {
    let config = default_config();
    let mut state = RuntimeState::new(&config);
    let user_db = UserDb::load();

    state.process_tree.insert(
        102,
        ProcessNode {
            pid: 102,
            ppid: 1,
            comm: "curl".into(),
            filename: "/usr/bin/curl".into(),
        },
    );

    conn_handler::handle_event(
        &conn_event(102, "curl", [127, 0, 0, 1], 80),
        &mut state,
        &user_db,
        &config,
    );
    conn_handler::handle_event(
        &conn_event(102, "curl", [1, 1, 1, 1], 0),
        &mut state,
        &user_db,
        &config,
    );

    assert!(!state.seen_network_callers.contains("curl"));
    assert_eq!(state.scorer.get_score(102), 0);
}
