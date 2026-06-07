package detection

import (
	"encoding/json"
	"fmt"

	"github.com/Prashant-koi/lavender/detection/internal/events"
)

func HandleCanonicalMessage(subject string, data []byte) ([]AlertEvent, error) {
	var evt events.CanonicalEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return nil, fmt.Errorf("invalid canonical json on %s: %w", subject, err)
	}

	var alerts []AlertEvent
	if alert := suspiciousPortAlert(evt); alert != nil {
		alerts = append(alerts, *alert)
	}
	if alert := sensitiveFileAlert(evt); alert != nil {
		alerts = append(alerts, *alert)
	}

	return alerts, nil
}
