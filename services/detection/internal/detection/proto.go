package detection

import (
	"fmt"

	"github.com/Prashant-koi/lavender/services/platform/events"
	"github.com/Prashant-koi/lavender/services/platform/pb"
	"google.golang.org/protobuf/proto"
)

// HandleCanonicalProto is the protobuf twin of HandleCanonicalMessage. It decodes a
// pb.CanonicalEvent into the internal events.CanonicalEvent the rule engine already
// consumes, so processEvent and every rule stay untouched. Only exec is on the proto
// path today; other kinds are skipped until converted.
func (d *Detector) HandleCanonicalProto(subject string, data []byte) ([]events.AlertEvent, error) {
	var pe pb.CanonicalEvent
	if err := proto.Unmarshal(data, &pe); err != nil {
		return nil, fmt.Errorf("invalid canonical proto on %s: %w", subject, err)
	}

	evt, ok := protoToCanonical(&pe)
	if !ok {
		return nil, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	return d.processEvent(evt), nil
}

func protoToCanonical(pe *pb.CanonicalEvent) (events.CanonicalEvent, bool) {
	raw := pe.Raw
	if raw == nil {
		return events.CanonicalEvent{}, false
	}

	hostname := ""
	if raw.Host != nil {
		hostname = raw.Host.Hostname
	}

	ce := events.CanonicalEvent{
		SchemaVersion:    uint16(raw.SchemaVersion),
		EventID:          raw.EventId,
		AgentID:          raw.AgentId,
		TenantID:         raw.TenantId,
		Host:             events.HostInfo{Hostname: hostname},
		ObservedAtUnixMs: int64(raw.ObservedAtUnixMs),
		ReceivedAtUnixMs: pe.ReceivedAtUnixMs,
	}

	switch e := raw.Event.(type) {
	case *pb.TelemetryEvent_Exec:
		ce.Event = events.TransportEventKind{
			Type:     "exec",
			PID:      e.Exec.Pid,
			PPID:     e.Exec.Ppid,
			UID:      e.Exec.Uid,
			Comm:     e.Exec.Comm,
			Filename: e.Exec.Filename,
			Argv:     e.Exec.Argv,
		}
		return ce, true
	case *pb.TelemetryEvent_Open:
		ce.Event = events.TransportEventKind{
			Type:     "open",
			PID:      e.Open.Pid,
			Comm:     e.Open.Comm,
			Filename: e.Open.Filename,
		}
		return ce, true
	case *pb.TelemetryEvent_Connect:
		ce.Event = events.TransportEventKind{
			Type:     "connect",
			PID:      e.Connect.Pid,
			UID:      e.Connect.Uid,
			Comm:     e.Connect.Comm,
			DestIP:   e.Connect.DestIp,
			DestPort: uint16(e.Connect.DestPort),
			AF:       uint16(e.Connect.Af),
		}
		return ce, true
	case *pb.TelemetryEvent_Exit:
		// exit drives per-pid state eviction in the correlator
		ce.Event = events.TransportEventKind{
			Type: "exit",
			PID:  e.Exit.Pid,
		}
		return ce, true
	default:
		return events.CanonicalEvent{}, false
	}
}
