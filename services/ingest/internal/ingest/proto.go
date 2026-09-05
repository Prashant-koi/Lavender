package ingest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Prashant-koi/lavender/services/platform/pb"
	"google.golang.org/protobuf/proto"
)

// HandleProtoMessage is the protobuf twin of HandleTransportMessage. It decodes a
// pb.TelemetryEvent, validates it, stamps the server receive time, and returns the
// accepted subject plus a marshalled pb.CanonicalEvent. event_id doubles as the
// JetStream dedup id on republish.
func HandleProtoMessage(subject string, data []byte, now func() int64) (string, []byte, string, error) {
	var raw pb.TelemetryEvent
	if err := proto.Unmarshal(data, &raw); err != nil {
		return "", nil, "", fmt.Errorf("invalid proto on %s: %w", subject, err)
	}

	if err := validateProtoEvent(&raw); err != nil {
		return "", nil, "", fmt.Errorf("couldn't validate on %s: %w", subject, err)
	}

	canonical := &pb.CanonicalEvent{
		Raw:              &raw,
		ReceivedAtUnixMs: now(),
	}

	payload, err := proto.Marshal(canonical)
	if err != nil {
		return "", nil, "", fmt.Errorf("marshal canonical proto failed: %w", err)
	}

	tenant := "unknown"
	if raw.TenantId != nil && *raw.TenantId != "" {
		tenant = *raw.TenantId
	}
	acceptedSubj := fmt.Sprintf("telemetry.accepted.%s.%s", tenant, raw.AgentId)

	return acceptedSubj, payload, raw.EventId, nil
}

func validateProtoEvent(evt *pb.TelemetryEvent) error {
	if evt.SchemaVersion == 0 {
		return errors.New("missing schema_version")
	}
	if strings.TrimSpace(evt.EventId) == "" {
		return errors.New("missing event_id")
	}
	if strings.TrimSpace(evt.AgentId) == "" {
		return errors.New("missing agent_id")
	}
	if evt.Host == nil || strings.TrimSpace(evt.Host.Hostname) == "" {
		return errors.New("missing host.hostname")
	}
	if evt.ObservedAtUnixMs == 0 {
		return errors.New("missing observed_at_unix_ms")
	}

	// per-kind required fields (exec is the first type on the proto path)
	switch e := evt.Event.(type) {
	case *pb.TelemetryEvent_Exec:
		if e.Exec.Pid == 0 {
			return errors.New("missing exec pid")
		}
		if strings.TrimSpace(e.Exec.Comm) == "" {
			return errors.New("missing exec comm")
		}
		if strings.TrimSpace(e.Exec.Filename) == "" {
			return errors.New("missing exec filename")
		}
		return nil
	case nil:
		return errors.New("missing event body")
	default:
		// other kinds are accepted through as they migrate to proto
		return nil
	}
}
