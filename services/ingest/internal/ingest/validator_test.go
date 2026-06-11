package ingest

import (
	"testing"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

func validExecEvent() events.AgentTelemetryEvent {
	tenant := "dev"
	return events.AgentTelemetryEvent{
		SchemaVersion:    1,
		AgentID:          "agent-1",
		TenantID:         &tenant,
		Host:             events.HostInfo{Hostname: "host-1"},
		ObservedAtUnixMs: 1234567890,
		Event: events.TransportEventKind{
			Type:     "exec",
			PID:      100,
			PPID:     50,
			UID:      1000,
			Comm:     "bash",
			Filename: "/bin/bash",
			Argv:     []string{"-c", "whoami"},
		},
	}
}

func TestValidateTransportEvents_ValidExec(t *testing.T) {
	evt := validExecEvent()

	if err := ValidateTransportEvents(evt); err != nil {
		t.Fatalf("expected valid exec event, got error: %v", err)
	}
}

func TestValidateTransportEvents_ValidHeartbeat(t *testing.T) {
	evt := validExecEvent()
	evt.Event = events.TransportEventKind{
		Type:   "heartbeat",
		Status: "alive",
	}

	if err := ValidateTransportEvents(evt); err != nil {
		t.Fatalf("expected valid heartbeat event, got error: %v", err)
	}
}

func TestValidateTransportEvents_MissingAgentID(t *testing.T) {
	evt := validExecEvent()
	evt.AgentID = ""

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected missing agent_id to fail validation")
	}
}

func TestValidateTransportEvents_MissingHostname(t *testing.T) {
	evt := validExecEvent()
	evt.Host.Hostname = ""

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected missing hostname to fail validation")
	}
}

func TestValidateTransportEvents_MissingObservedAt(t *testing.T) {
	evt := validExecEvent()
	evt.ObservedAtUnixMs = 0

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected missing observed_at_unix_ms to fail validation")
	}
}

func TestValidateTransportEvents_MissingExecPID(t *testing.T) {
	evt := validExecEvent()
	evt.Event.PID = 0

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected missing exec pid to fail validation")
	}
}

func TestValidateTransportEvents_MissingExecComm(t *testing.T) {
	evt := validExecEvent()
	evt.Event.Comm = ""

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected missing exec comm to fail validation")
	}
}

func TestValidateTransportEvents_MissingExecFilename(t *testing.T) {
	evt := validExecEvent()
	evt.Event.Filename = ""

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected missing exec filename to fail validation")
	}
}

func TestValidateTransportEvents_MissingHeartbeatStatus(t *testing.T) {
	evt := validExecEvent()
	evt.Event = events.TransportEventKind{
		Type:   "heartbeat",
		Status: "",
	}

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected missing heartbeat status to fail validation")
	}
}

func TestValidateTransportEvents_UnsupportedType(t *testing.T) {
	evt := validExecEvent()
	evt.Event.Type = "weird_event"

	if err := ValidateTransportEvents(evt); err == nil {
		t.Fatal("expected unsupported event type to fail validation")
	}
}
