use serde::Serialize;

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
pub fn print_exec(pid: u32, ppid: u32, comm: &str, filename: &str, ancestry: &str) {
    let event = ExecOutput {
        kind: "exec",
        pid,
        ppid,
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