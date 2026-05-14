package ingest

import (
	"testing"

	"github.com/Prashant-koi/lavender/ingest/internal/events"
)

func TestCanonicalSubject_WithTenant(t *testing.T) {
	tenant := "dev"
	evt := events.AgentTelemetryEvent{
		AgentID:  "agent-1",
		TenantID: &tenant,
	}

	got := CanonicalSubject(evt)
	want := "telemetry.accepted.dev.agent-1"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestCanonicalSubject_WithoutTenant(t *testing.T) {
	evt := events.AgentTelemetryEvent{
		AgentID:  "agent-1",
		TenantID: nil,
	}

	got := CanonicalSubject(evt)
	want := "telemetry.accepted.unknown.agent-1"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
