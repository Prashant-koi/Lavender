use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTelemetryEvent {
    pub schema_version: u16,
    pub agent_id: String,
    pub tenant_id: Option<String>,
    pub host: HostInfo,
    pub observed_at_unix_ms: u64,
    pub event: TransportEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportEventKind {
    Exec(ExecTransportEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecTransportEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    pub argv: Vec<String>,
}
