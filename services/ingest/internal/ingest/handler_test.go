package ingest

import (
	"encoding/json"
	"testing"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

func TestHandleTransportMessageExec(t *testing.T) {
	now := int64(1234567890)
	tenant := "dev"

	raw := events.AgentTelemetryEvent{
		EventID:       "11111111-2222-3333-4444-555555555555",
		SchemaVersion: 1,
		AgentID:       "agent-1",
		TenantID:      &tenant,
		Host: events.HostInfo{
			Hostname: "host-1",
		},
		ObservedAtUnixMs: 1111111111,
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

	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	subject, payload, _, err := HandleTransportMessage(
		"telemetry.raw.dev.agent-1",
		data,
		func() int64 { return now },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if subject != "telemetry.accepted.dev.agent-1" {
		t.Fatalf("unexpected subject: %s", subject)
	}

	var canonical events.CanonicalEvent
	if err := json.Unmarshal(payload, &canonical); err != nil {
		t.Fatalf("failed to unmarshal canonical payload: %v", err)
	}

	if canonical.ReceivedAtUnixMs != now {
		t.Fatalf("expected received_at %d, got %d", now, canonical.ReceivedAtUnixMs)
	}

	if canonical.Event.Type != "exec" {
		t.Fatalf("expected exec event type, got %s", canonical.Event.Type)
	}
}

func TestHandleTransportMessageHeartbeat(t *testing.T) {
	now := int64(2222222222)
	tenant := "dev"

	raw := events.AgentTelemetryEvent{
		EventID:       "11111111-2222-3333-4444-555555555555",
		SchemaVersion: 1,
		AgentID:       "agent-2",
		TenantID:      &tenant,
		Host: events.HostInfo{
			Hostname: "host-2",
		},
		ObservedAtUnixMs: 1111111111,
		Event: events.TransportEventKind{
			Type:   "heartbeat",
			Status: "alive",
		},
	}

	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	subject, payload, _, err := HandleTransportMessage(
		"telemetry.raw.dev.agent-2",
		data,
		func() int64 { return now },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if subject != "telemetry.accepted.dev.agent-2" {
		t.Fatalf("unexpected subject: %s", subject)
	}

	var canonical events.CanonicalEvent
	if err := json.Unmarshal(payload, &canonical); err != nil {
		t.Fatalf("failed to unmarshal canonical payload: %v", err)
	}

	if canonical.Event.Type != "heartbeat" {
		t.Fatalf("expected heartbeat event type, got %s", canonical.Event.Type)
	}

	if canonical.Event.Status != "alive" {
		t.Fatalf("expected alive status, got %s", canonical.Event.Status)
	}
}

func TestHandleTransportMessageInvalidJSON(t *testing.T) {
	_, _, _, err := HandleTransportMessage(
		"telemetry.raw.dev.agent-1",
		[]byte(`{"bad_json":`),
		func() int64 { return 1 },
	)
	if err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestHandleTransportMessageValidationFailure(t *testing.T) {
	raw := events.AgentTelemetryEvent{
		EventID:       "11111111-2222-3333-4444-555555555555",
		SchemaVersion: 1,
		AgentID:       "",
		Host: events.HostInfo{
			Hostname: "host-1",
		},
		ObservedAtUnixMs: 1111111111,
		Event: events.TransportEventKind{
			Type: "exec",
		},
	}

	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = HandleTransportMessage(
		"telemetry.raw.dev.agent-1",
		data,
		func() int64 { return 1 },
	)
	if err == nil {
		t.Fatal("expected validation error")
	}
}
