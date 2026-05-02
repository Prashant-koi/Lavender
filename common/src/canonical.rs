use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    pub schema_version: u16, //transpot format version
    pub agent_id: String, // agent here means the device in the data plane in the arch btw
    pub tenant_id: Option<String>, 
    pub host: HostInfo,
    pub observed_at_unix_ms: u64, // when the agent observed
    pub received_at_unix_ms: Option<u64>, // when the ingest tier recieved
    pub event: EventKind,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String, // i know this looks weird rn but hostinfo might grow later so I am doing this
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="type", rename_all="snake_case")]
pub enum EventKind {
    Exec(ExecTelemetry),
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecTelemetry {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    pub argv: Vec<String>,
} 