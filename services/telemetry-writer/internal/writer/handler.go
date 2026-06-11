package writer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

type CanonicalRow struct {
	EventType        string
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
	DestIP           string
	DestPort         uint16
	AF               uint16
}

func HandleCanonicalMessage(subject string, data []byte) (*CanonicalRow, error) {
	var evt events.CanonicalEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return nil, fmt.Errorf("invalid canonical json on %s : %w", subject, err)
	}

	tenantID := "unknown"
	if evt.TenantID != nil && *evt.TenantID != "" {
		tenantID = *evt.TenantID
	}

	row := &CanonicalRow{
		EventType:        evt.Event.Type,
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
		DestIP:           evt.Event.DestIP,
		DestPort:         evt.Event.DestPort,
		AF:               evt.Event.AF,
	}

	switch evt.Event.Type {
	case "exec", "open", "connect":
		return row, nil
	default:
		return nil, nil
	}
}
