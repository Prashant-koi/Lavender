package ingest

import (
	"errors"
	"strings"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

func ValidateTransportEvents(evt events.AgentTelemetryEvent) error {
	// check schema version and all other fileds sicne they all required
	if evt.SchemaVersion == 0 {
		return errors.New("missing schema_version")
	}

	if strings.TrimSpace(evt.EventID) == "" {
		return errors.New("missing event_id")
	}

	if strings.TrimSpace(evt.AgentID) == "" {
		return errors.New("missing agent_id")
	}

	if strings.TrimSpace(evt.Host.Hostname) == "" {
		return errors.New("missing host.hostname")
	}

	if evt.ObservedAtUnixMs == 0 {
		return errors.New("missing observered_at_unix_ms")
	}

	switch evt.Event.Type {
	case "exec":
		if evt.Event.PID == 0 {
			return errors.New("missing exec pid")
		}
		if strings.TrimSpace(evt.Event.Comm) == "" {
			return errors.New("Missisng exec comm")
		}
		if strings.TrimSpace(evt.Event.Filename) == "" {
			return errors.New("missing exec filename")
		}
		return nil

	case "heartbeat":
		if strings.TrimSpace(evt.Event.Status) == "" {
			return errors.New("missing heartbeat status")
		}
		return nil

	case "open":
		if evt.Event.PID == 0 {
			return errors.New("missing open pid")
		}
		if strings.TrimSpace(evt.Event.Comm) == "" {
			return errors.New("missing open comm")
		}
		if strings.TrimSpace(evt.Event.Filename) == "" {
			return errors.New("missing open filename")
		}
		return nil

	case "exit":
		if evt.Event.PID == 0 {
			return errors.New("missing exit pid")
		}
		return nil

	case "connect":
		if evt.Event.PID == 0 {
			return errors.New("missing connect pid")
		}
		if strings.TrimSpace(evt.Event.Comm) == "" {
			return errors.New("missing connect comm")
		}
		if strings.TrimSpace(evt.Event.DestIP) == "" {
			return errors.New("missing connect dest_ip")
		}
		return nil

	default:
		return errors.New("unsupported Event Type")
	}

}
