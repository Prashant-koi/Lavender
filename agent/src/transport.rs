use common::transport::{
    AgentTelemetryEvent,
    ExecTransportEvent,
    HostInfo,
    TransportEventKind,
};
use common::ExecEvent;

//for now only gonna make one for exec events as a starating point
pub fn exec_to_transport_event(
    event: &ExecEvent,
    agent_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        schema_version: 1,
        agent_id: agent_id.to_string(),
        tenant_id: None,
        host: HostInfo {
            hostname: hostname.to_string(),
        },
        observed_at_unix_ms,
        event: TransportEventKind::Exec(ExecTransportEvent {
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            comm: bytes_to_string(&event.comm),
            filename: bytes_to_string(&event.filename),
            argv: vec![bytes_to_string(&event.argv1), bytes_to_string(&event.argv2)]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect(),
        }),
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}
