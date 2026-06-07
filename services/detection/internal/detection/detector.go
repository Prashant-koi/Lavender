package detection

import (
	"sync"

	"github.com/Prashant-koi/lavender/detection/internal/events"
)

type Detector struct {
	mu        sync.Mutex
	processes map[uint32]string
}

func NewDetector() *Detector {
	return &Detector{
		processes: make(map[uint32]string),
	}
}

func (d *Detector) processEvent(evt events.CanonicalEvent) []AlertEvent {
	var alerts []AlertEvent

	if alert := suspiciousPortAlert(evt); alert != nil {
		alerts = append(alerts, *alert)
	}
	if alert := shellNetworkConnectionAlert(evt); alert != nil {
		alerts = append(alerts, *alert)
	}
	if alert := sensitiveFileAlert(evt); alert != nil {
		alerts = append(alerts, *alert)
	}
	if alert := d.unexpectedShellSpawnAlert(evt); alert != nil {
		alerts = append(alerts, *alert)
	}

	d.observeProcess(evt)
	return alerts
}

func (d *Detector) observeProcess(evt events.CanonicalEvent) {
	if evt.Event.Type != "exec" || evt.Event.PID == 0 || evt.Event.Comm == "" {
		return
	}

	d.processes[evt.Event.PID] = evt.Event.Comm
}
