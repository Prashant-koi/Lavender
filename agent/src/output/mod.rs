use std::str;

use serde::Serialize;
use common::ConnEvent;
use self::format::{format_ip, now_secs};

pub mod format;

#[derive(Serialize)]
pub struct ExecOutput<'a> {
    #[serde(rename = "type")]
    pub kind: &'static str,   // always be "exec"
    pub pid: u32,
    pub ppid: u32,
    pub user: &'a str,
    pub comm: &'a str,
    pub filename: &'a str,
    pub cmdline: &'a str,
    pub ancestry: &'a str,
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct AlertOutput<'a> {
    #[serde(rename = "type")]
    pub kind: &'static str,   // always be "alert"
    pub pid: u32,
    pub rule: &'a str,
    pub detail: &'a str,
    pub ancestry: &'a str,
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct ScoredAlertOutput<'a> {
    #[serde(rename= "type")]
    pub kind:     &'static str,
    pub pid:      u32,
    pub rule:     &'a str,
    pub detail:   &'a str,
    pub ancestry: &'a str,
    pub score:    u32,
    pub severity: &'a str,   // "INFO", "WARNING", "HIGH", "CRITICAL"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineage_bonus: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rarity_bonus: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_bonus: Option<u32>,
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct ResponseOutput<'a> {
    pub kind: &'static str,
    pub pid: u32,
    pub comm: &'a str,
    pub action: &'a str,
    pub dry_run: bool,
    pub score: u32,
    pub timestamp: u64,
}

//will print exec in json format
pub fn print_exec(pid: u32, ppid: u32, user: &str, comm: &str, filename: &str, cmdline: &str, ancestry: &str) {
    let event = ExecOutput {
        kind: "exec",
        pid,
        ppid,
        user,
        comm,
        filename,
        cmdline,
        ancestry,
        timestamp: now_secs(),
    };
    println!("{}", serde_json::to_string(&event).unwrap()); //to_string() won't fail 
}

//will print alert in json format
pub fn print_alert(pid: u32, rule: &str, detail: &str, ancestry: &str) {
    let event = AlertOutput {
        kind: "alert",
        pid,
        rule,
        detail,
        ancestry,
        timestamp: now_secs(),
    };
    // for this one we will print to stderr so alerts are seperate form the event streams
    // this will make sure you pipe stdout to a file and are still able to see alerts in the terminal
    // use this command from root of repo to get all alerts in a json file
    // sudo ./agent/target/debug/lavender-loader 1>/dev/null 2>alerts.json
    eprintln!("\x1b[31m{}\x1b[0m", serde_json::to_string(&event).unwrap());
}

pub fn print_scored_alert(
    pid:      u32,
    rule:     &str,
    detail:   &str,
    ancestry: &str,
    score:    u32,
    severity: &str,
    base_score: Option<u32>,
    lineage_bonus: Option<u32>,
    rarity_bonus: Option<u32>,
    sequence_bonus: Option<u32>,
) {
    let out = ScoredAlertOutput {
        kind: "alert",
        pid,
        rule,
        detail,
        ancestry,
        score,
        severity,
        base_score,
        lineage_bonus,
        rarity_bonus,
        sequence_bonus,
        timestamp: now_secs(),
    };

    // color based on severity
    let color = match severity {
        "CRITICAL" => "\x1b[31m",  // red
        "HIGH"     => "\x1b[33m",  // yellow
        "WARNING"  => "\x1b[93m",  // bright yellow
        _          => "\x1b[0m",   // no color for info
    };

    eprintln!("{}{}\x1b[0m",
        color,
        serde_json::to_string(&out).unwrap()
    );
}

pub fn print_kill (
    pid: u32,
    comm: &str,
    score:    u32,
    dry_run: bool,
) {
    let action = if dry_run {"would kill"} else {"Killed"};
    let out = ResponseOutput {
        kind: "response",
        pid,
        comm,
        action,
        dry_run,
        score,
        timestamp: now_secs(),
    };

    // print and we will use bright red for acutal kills and yellow for dry runs
    let color = if dry_run { "\x1b[33m" } else { "\x1b[31m" }; //props to claude for color codes
    eprintln!("{}{}\x1b[0m", color, serde_json::to_string(&out).unwrap());
}

#[derive(Serialize)]
pub struct ConnOutput<'a> {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub pid: u32,
    pub user: &'a str,
    pub comm: &'a str,
    pub dest_ip: String,
    pub dest_port: u16,
    pub timestamp: u64,
}

pub fn print_conn(event: &ConnEvent, comm: &str, user: &str) {
    let out = ConnOutput {
        kind: "conn",
        pid: event.pid,
        user,
        comm,
        dest_ip: format_ip(event),
        dest_port: event.dport,
        timestamp: now_secs(),
    };
    println!("{}", serde_json::to_string(&out).unwrap());
}