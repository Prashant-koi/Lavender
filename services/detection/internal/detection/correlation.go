package detection

import (
	"fmt"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

type eventKind string

const (
	eventExec eventKind = "exec"
	eventOpen eventKind = "open"
)

const correlatorMaxAgeMs int64 = 30_000

type bufferedEvent struct {
	kind      eventKind
	comm      string
	detail    string
	timestamp int64
}

func (d *Detector) pushCorrelatedEvent(evt events.CanonicalEvent) *events.AlertEvent {
	buffered, ok := eventToBuffer(evt)
	if !ok {
		return nil
	}

	key := keyFor(evt, evt.Event.PID)
	buf := d.buffers[key]
	buf = pruneBuffer(buf, evt.ReceivedAtUnixMs)
	buf = append(buf, buffered)
	if len(buf) > d.maxEvents {
		buf = buf[len(buf)-d.maxEvents:]
	}
	d.buffers[key] = buf

	return d.credentialAccessThenExecutionAlert(evt, buf)
}

func eventToBuffer(evt events.CanonicalEvent) (bufferedEvent, bool) {
	switch evt.Event.Type {
	case "exec":
		return bufferedEvent{
			kind:      eventExec,
			comm:      evt.Event.Comm,
			detail:    evt.Event.Filename,
			timestamp: evt.ReceivedAtUnixMs,
		}, true
	case "open":
		return bufferedEvent{
			kind:      eventOpen,
			comm:      evt.Event.Comm,
			detail:    evt.Event.Filename,
			timestamp: evt.ReceivedAtUnixMs,
		}, true
	default:
		return bufferedEvent{}, false
	}
}

func pruneBuffer(buf []bufferedEvent, nowUnixMs int64) []bufferedEvent {
	firstFresh := 0
	for firstFresh < len(buf) && nowUnixMs-buf[firstFresh].timestamp > correlatorMaxAgeMs {
		firstFresh++
	}

	return buf[firstFresh:]
}

func (d *Detector) credentialAccessThenExecutionAlert(evt events.CanonicalEvent, buf []bufferedEvent) *events.AlertEvent {
	if evt.Event.Type != "exec" {
		return nil
	}

	for i := 0; i < len(buf)-1; i++ {
		if buf[i].kind != eventOpen || !containsAny(buf[i].detail, sensitiveFiles) {
			continue
		}

		detail := fmt.Sprintf(
			"process read sensitive file then executed a new process: %s -> %s",
			buf[i].detail,
			evt.Event.Filename,
		)
		alert := newAlert(
			evt,
			"CHAIN Credential access then execution",
			"high",
			detail,
		)

		return &alert
	}

	return nil
}
