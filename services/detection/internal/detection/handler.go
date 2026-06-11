package detection

import (
	"encoding/json"
	"fmt"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

func HandleCanonicalMessage(subject string, data []byte) ([]events.AlertEvent, error) {
	return NewDetector().HandleCanonicalMessage(subject, data)
}

func (d *Detector) HandleCanonicalMessage(subject string, data []byte) ([]events.AlertEvent, error) {
	var evt events.CanonicalEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return nil, fmt.Errorf("invalid canonical json on %s: %w", subject, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	return d.processEvent(evt), nil
}
