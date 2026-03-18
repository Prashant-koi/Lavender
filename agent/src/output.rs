use std::str;

use serde::Serialize;
use common::ConnEvent;

//every event will get a unix timestamp
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Serialize)]
pub struct ExecOutput<'a> {
    #[serde(rename = "type")]
    pub kind: &'static str,   // always be "exec"
    pub pid: u32,
    pub ppid: u32,
    pub user: &'a str,
    pub comm: &'a str,
    pub filename: &'a str,
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

//will print exec in json format
pub fn print_exec(pid: u32, ppid: u32, user: &str, comm: &str, filename: &str, ancestry: &str) {
    let event = ExecOutput {
        kind: "exec",
        pid,
        ppid,
        user,
        comm,
        filename,
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

//formatting of ip from the 4/16 byts of IPv4/IPv6
pub fn format_ip(event: &ConnEvent) -> String {
    if event.af == 2 {
        //IPV4, which is first 4 bytes
        format!("{}.{}.{}.{}",
            event.daddr[0],
            event.daddr[1],
            event.daddr[2],
            event.daddr[3],
        )
    } else {
        //IPv6, all 16 bytes as hex pairs
        let b = &event.daddr;
        format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],
            b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]
        ) // props to Claude for writing this!
    }
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