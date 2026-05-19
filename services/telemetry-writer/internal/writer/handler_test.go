package writer

import (
	"encoding/json"
	"testing"

	"github.com/Prashant-koi/lavender/telemetry-writer/internal/events"
)

func TestHandleCanonicalMessageExec(t *testing.T) {
	tenant := "dev"

	evt := events.CanonicalEvent{
		SchemaVersion:    1,
		AgentID:          "agent-1",
		TenantID:         &tenant,
		Host:             events.HostInfo{Hostname: "host-1"},
		ObservedAtUnixMs: 100,
		ReceivedAtUnixMs: 200,
		Event: events.TransportEventKind{
			Type:     "exec",
			PID:      123,
			PPID:     1,
			UID:      1000,
			Comm:     "bash",
			Filename: "/bin/bash",
			Argv:     []string{"-c", "whoami"},
		},
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}

	row, err := HandleCanonicalMessage("telemetry.accepted.dev.agent-1", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row == nil {
		t.Fatal("expected exec row, got nil")
	}

	if row.AgentID != "agent-1" {
		t.Fatalf("unexpected agent id: %s", row.AgentID)
	}
	if row.Argv != "-c whoami" {
		t.Fatalf("unexpected argv: %s", row.Argv)
	}
}

func TestHandleCanonicalMessageHeartbeatReturnsNil(t *testing.T) {
	tenant := "dev"

	evt := events.CanonicalEvent{
		SchemaVersion:    1,
		AgentID:          "agent-1",
		TenantID:         &tenant,
		Host:             events.HostInfo{Hostname: "host-1"},
		ObservedAtUnixMs: 100,
		ReceivedAtUnixMs: 200,
		Event: events.TransportEventKind{
			Type:   "heartbeat",
			Status: "alive",
		},
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}

	row, err := HandleCanonicalMessage("telemetry.accepted.dev.agent-1", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row != nil {
		t.Fatal("expected nil row for heartbeat event")
	}
}

func TestHandleCanonicalMessageInvalidJSON(t *testing.T) {
	_, err := HandleCanonicalMessage("telemetry.accepted.dev.agent-1", []byte(`{"bad_json":`))
	if err == nil {
		t.Fatal("expected invalid json error")
	}
}
