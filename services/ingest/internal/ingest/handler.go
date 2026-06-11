package ingest

import (
	"encoding/json"
	"fmt"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

// we just take in the subject the raw data and the time fuinction
// and then we validate the data and make a canonical event data for the
// backend then then we reutn the acceptedSubj(which in this case is just gonna say telemetry accepted and some
// other stuff ), then the actual canonical event payload and the error (if there are any)
func HandleTransportMessage(
	subject string,
	data []byte,
	now func() int64,
) (string, []byte, error) {
	//decode
	var raw events.AgentTelemetryEvent
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", nil, fmt.Errorf("invalid json on %s : %w", subject, err)
	}

	//validate
	if err := ValidateTransportEvents(raw); err != nil {
		return "", nil, fmt.Errorf("couldn't validate on %s : %w", subject, err)
	}

	//we will now convert the raw transpoet events ino the canonical backend ebent
	canonical := events.CanonicalEvent{
		SchemaVersion:    raw.SchemaVersion,
		AgentID:          raw.AgentID,
		TenantID:         raw.TenantID,
		Host:             raw.Host,
		ObservedAtUnixMs: raw.ObservedAtUnixMs,
		ReceivedAtUnixMs: now(),
		Event:            raw.Event,
	}

	acceptedSubj := CanonicalSubject(raw)

	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", nil, fmt.Errorf("Matshall of Canonical failed: %w", err)
	}

	return acceptedSubj, payload, nil

}
