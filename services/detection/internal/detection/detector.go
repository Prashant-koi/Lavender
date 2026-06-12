package detection

import (
	"sync"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

// pids are only unique within one machine, two agents will happily both have
// a pid 4242. keying by pid alone would mix process state across hosts, so
// every map key carries the tenant and agent too
type processKey struct {
	tenant  string
	agentID string
	pid     uint32
}

type Detector struct {
	mu        sync.Mutex
	processes map[processKey]string
	buffers   map[processKey][]bufferedEvent
	maxEvents int
}

func NewDetector() *Detector {
	return &Detector{
		processes: make(map[processKey]string),
		buffers:   make(map[processKey][]bufferedEvent),
		maxEvents: 20,
	}
}

func keyFor(evt events.CanonicalEvent, pid uint32) processKey {
	tenant := "unknown"
	if evt.TenantID != nil && *evt.TenantID != "" {
		tenant = *evt.TenantID
	}

	return processKey{
		tenant:  tenant,
		agentID: evt.AgentID,
		pid:     pid,
	}
}

func (d *Detector) processEvent(evt events.CanonicalEvent) []events.AlertEvent {
	// exit means the process is gone, drop its state so the maps don't grow
	// forever and a recycled pid can't inherit a dead process's comm
	if evt.Event.Type == "exit" {
		key := keyFor(evt, evt.Event.PID)
		delete(d.processes, key)
		delete(d.buffers, key)
		return nil
	}

	var alerts []events.AlertEvent

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
	if alert := d.pushCorrelatedEvent(evt); alert != nil {
		alerts = append(alerts, *alert)
	}

	d.observeProcess(evt)
	return alerts
}

func (d *Detector) observeProcess(evt events.CanonicalEvent) {
	if evt.Event.Type != "exec" || evt.Event.PID == 0 || evt.Event.Comm == "" {
		return
	}

	d.processes[keyFor(evt, evt.Event.PID)] = evt.Event.Comm
}
