package writer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Prashant-koi/lavender/telemetry-writer/internal/events"
)

type ExecRow struct {
	AgentID          string
	TenantID         string
	Hostname         string
	ObservedAtUnixMs int64
	ReceivedAtUnixMs int64
	PID              uint32
	PPID             uint32
	UID              uint32
	Comm             string
	Filename         string
	Argv             string
}

func HandleCanonicalMessage(subject string, data []byte) (*ExecRow, error) {
	var evt events.CanonicalEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return nil, fmt.Errorf("invalid canonical json on %s : %w", subject, err)
	}

	if evt.Event.Type != "exec" { // TODO: might need to change this later
		return nil, nil
	}

	tenantID := "unknown"
	if evt.TenantID != nil && *evt.TenantID != "" {
		tenantID = *evt.TenantID
	}

	row := &ExecRow{
		AgentID:          evt.AgentID,
		TenantID:         tenantID,
		Hostname:         evt.Host.Hostname,
		ObservedAtUnixMs: evt.ObservedAtUnixMs,
		ReceivedAtUnixMs: evt.ReceivedAtUnixMs,
		PID:              evt.Event.PID,
		PPID:             evt.Event.PPID,
		UID:              evt.Event.UID,
		Comm:             evt.Event.Comm,
		Filename:         evt.Event.Filename,
		Argv:             strings.Join(evt.Event.Argv, " "),
	}

	return row, nil
}
