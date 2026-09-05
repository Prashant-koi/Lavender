package writer

import (
	"fmt"
	"strings"

	"github.com/Prashant-koi/lavender/services/platform/pb"
	"google.golang.org/protobuf/proto"
)

// HandleCanonicalProto is the protobuf twin of HandleCanonicalMessage: it decodes a
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
	default:
		// open/connect and the new probe types aren't persisted via proto yet
		return nil, nil
	}
}
