use common::ExecEvent;
use prost::Message;

use crate::pb;

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// Build the protobuf TelemetryEvent envelope for an exec event and return its
/// (event_id, encoded bytes). The event_id doubles as the JetStream dedup id.
pub fn exec_to_proto(
    event: &ExecEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> (String, Vec<u8>) {
    let event_id = uuid::Uuid::new_v4().to_string();

    let cmdline = bytes_to_string(&event.cmdline);
    let argv: Vec<String> = cmdline
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let telemetry = pb::TelemetryEvent {
        schema_version: 1,
        event_id: event_id.clone(),
        agent_id: agent_id.to_string(),
        tenant_id: Some(tenant_id.to_string()),
        host: Some(pb::Host { hostname: hostname.to_string() }),
        observed_at_unix_ms,
        ktime_ns: event.ktime_ns,
        event: Some(pb::telemetry_event::Event::Exec(pb::ExecEvent {
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            comm: bytes_to_string(&event.comm),
            filename: bytes_to_string(&event.filename),
            argv,
        })),
    };

    (event_id, telemetry.encode_to_vec())
}
