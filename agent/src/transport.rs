use crate::output::format::format_ip;
use common::transport::{
    AgentTelemetryEvent,
    ConnectTransportEvent,
    ExecTransportEvent,
    HeartbeatTransportEvent,
    HostInfo,
    OpenTransportEvent,
    TransportEventKind,
};
use common::{ConnEvent, ExecEvent, OpenEvent};

//exec events transport
pub fn exec_to_transport_event(
    event: &ExecEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        schema_version: 1,
        agent_id: agent_id.to_string(),
        tenant_id: Some(tenant_id.to_string()),
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

// the heartbeat messages will let the control plane track last seen state
pub fn heartbeat_transport_event(
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        schema_version: 1,
        agent_id: agent_id.to_string(),
        tenant_id: Some(tenant_id.to_string()),
        host: HostInfo {
            hostname: hostname.to_string(),
        },
        observed_at_unix_ms,
        event: TransportEventKind::Heartbeat(HeartbeatTransportEvent {
            status: "alive".to_string(),
        }),
    }
}

//open events transport
pub fn open_to_transport_event(
    event: &OpenEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        schema_version: 1,
        agent_id: agent_id.to_string(),
        tenant_id: Some(tenant_id.to_string()),
        host: HostInfo {
            hostname: hostname.to_string(),
        },
        observed_at_unix_ms,
        event: TransportEventKind::Open(OpenTransportEvent {
            pid: event.pid,
            comm: bytes_to_string(&event.comm),
            filename: bytes_to_string(&event.filename),
        }),
    }
}

//connect event transport
pub fn connect_to_transport_event(
    event: &ConnEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        schema_version: 1,
        agent_id: agent_id.to_string(),
        tenant_id: Some(tenant_id.to_string()),
        host: HostInfo {
            hostname: hostname.to_string(),
        },
        observed_at_unix_ms,
        event: TransportEventKind::Connect(ConnectTransportEvent {
            pid: event.pid,
            uid: event.uid,
            comm: bytes_to_string(&event.comm),
            dest_ip: format_ip(event),
            dest_port: event.dport,
            af: event.af,
        }),
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}
