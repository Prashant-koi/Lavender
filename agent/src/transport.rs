use common::transport::{
    AgentTelemetryEvent,
    HeartbeatTransportEvent,
    HostInfo,
    TransportEventKind,
};

// the heartbeat messages let the control plane track last-seen state. heartbeat still
// rides core NATS as JSON; all telemetry (exec/open/connect/exit) is on protobuf now.
pub fn heartbeat_transport_event(
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> AgentTelemetryEvent {
    AgentTelemetryEvent {
        schema_version: 1,
        event_id: uuid::Uuid::new_v4().to_string(),
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
