use common::{ConnEvent, ExecEvent, ExitEvent, OpenEvent};
use prost::Message;

use crate::output::format::format_ip;
use crate::pb;

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

// Wrap a per-kind body in the TelemetryEvent envelope. event_id doubles as the
// JetStream dedup id.
fn envelope(
    event_id: &str,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
    ktime_ns: u64,
    body: pb::telemetry_event::Event,
) -> pb::TelemetryEvent {
    pb::TelemetryEvent {
        schema_version: 1,
        event_id: event_id.to_string(),
        agent_id: agent_id.to_string(),
        tenant_id: Some(tenant_id.to_string()),
        host: Some(pb::Host { hostname: hostname.to_string() }),
        observed_at_unix_ms,
        ktime_ns,
        event: Some(body),
    }
}

pub fn exec_to_proto(
    event: &ExecEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> (String, Vec<u8>) {
    let event_id = uuid::Uuid::new_v4().to_string();
    let cmdline = bytes_to_string(&event.cmdline);
    let argv: Vec<String> = cmdline.split_whitespace().map(|s| s.to_string()).collect();

    let t = envelope(
        &event_id, agent_id, tenant_id, hostname, observed_at_unix_ms, event.ktime_ns,
        pb::telemetry_event::Event::Exec(pb::ExecEvent {
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            comm: bytes_to_string(&event.comm),
            filename: bytes_to_string(&event.filename),
            argv,
        }),
    );
    (event_id, t.encode_to_vec())
}

pub fn open_to_proto(
    event: &OpenEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> (String, Vec<u8>) {
    let event_id = uuid::Uuid::new_v4().to_string();
    let t = envelope(
        &event_id, agent_id, tenant_id, hostname, observed_at_unix_ms, event.ktime_ns,
        pb::telemetry_event::Event::Open(pb::OpenEvent {
            pid: event.pid,
            comm: bytes_to_string(&event.comm),
            filename: bytes_to_string(&event.filename),
            flags: event.flags,
        }),
    );
    (event_id, t.encode_to_vec())
}

pub fn connect_to_proto(
    event: &ConnEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> (String, Vec<u8>) {
    let event_id = uuid::Uuid::new_v4().to_string();
    let t = envelope(
        &event_id, agent_id, tenant_id, hostname, observed_at_unix_ms, event.ktime_ns,
        pb::telemetry_event::Event::Connect(pb::ConnectEvent {
            pid: event.pid,
            uid: event.uid,
            comm: bytes_to_string(&event.comm),
            dest_ip: format_ip(event),
            dest_port: event.dport as u32,
            af: event.af as u32,
        }),
    );
    (event_id, t.encode_to_vec())
}

pub fn exit_to_proto(
    event: &ExitEvent,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    observed_at_unix_ms: u64,
) -> (String, Vec<u8>) {
    let event_id = uuid::Uuid::new_v4().to_string();
    let t = envelope(
        &event_id, agent_id, tenant_id, hostname, observed_at_unix_ms, event.ktime_ns,
        pb::telemetry_event::Event::Exit(pb::ExitEvent { pid: event.pid }),
    );
    (event_id, t.encode_to_vec())
}
