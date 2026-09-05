package writer

import (
	"fmt"
	"strings"

	"github.com/Prashant-koi/lavender/services/platform/pb"
	"google.golang.org/protobuf/proto"
)

// HandleCanonicalProto decodes a
// pb.CanonicalEvent into the format-agnostic CanonicalRow the store already inserts.
// Only exec is on the proto path today; other kinds return (nil, nil) = skip.
func HandleCanonicalProto(subject string, data []byte) (*CanonicalRow, error) {
	var evt pb.CanonicalEvent
	if err := proto.Unmarshal(data, &evt); err != nil {
		return nil, fmt.Errorf("invalid canonical proto on %s: %w", subject, err)
	}

	raw := evt.Raw
	if raw == nil {
		return nil, nil
	}

	tenant := "unknown"
	if raw.TenantId != nil && *raw.TenantId != "" {
		tenant = *raw.TenantId
	}
	hostname := ""
	if raw.Host != nil {
		hostname = raw.Host.Hostname
	}

	row := &CanonicalRow{
		AgentID:          raw.AgentId,
		TenantID:         tenant,
		Hostname:         hostname,
		ObservedAtUnixMs: int64(raw.ObservedAtUnixMs),
		ReceivedAtUnixMs: evt.ReceivedAtUnixMs,
	}

	switch e := raw.Event.(type) {
	case *pb.TelemetryEvent_Exec:
		row.EventType = "exec"
		row.PID = e.Exec.Pid
		row.PPID = e.Exec.Ppid
		row.UID = e.Exec.Uid
		row.Comm = e.Exec.Comm
		row.Filename = e.Exec.Filename
		row.Argv = strings.Join(e.Exec.Argv, " ")
		return row, nil
	case *pb.TelemetryEvent_Open:
		row.EventType = "open"
		row.PID = e.Open.Pid
		row.Comm = e.Open.Comm
		row.Filename = e.Open.Filename
		return row, nil
	case *pb.TelemetryEvent_Connect:
		row.EventType = "connect"
		row.PID = e.Connect.Pid
		row.UID = e.Connect.Uid
		row.Comm = e.Connect.Comm
		row.DestIP = e.Connect.DestIp
		row.DestPort = uint16(e.Connect.DestPort)
		row.AF = uint16(e.Connect.Af)
		return row, nil
	default:
		// exit/heartbeat and the new probe types aren't persisted yet
		return nil, nil
	}
}
