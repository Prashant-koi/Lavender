package detection

import (
	"fmt"

	"github.com/Prashant-koi/lavender/detection/internal/events"
)

var suspiciousPorts = map[uint16]struct{}{
	4444:  {},
	1337:  {},
	9001:  {},
	9999:  {},
	6666:  {},
	31337: {},
	5555:  {},
}

func suspiciousPortAlert(evt events.CanonicalEvent) *AlertEvent {
	if evt.Event.Type != "connect" {
		return nil
	}

	if _, ok := suspiciousPorts[evt.Event.DestPort]; !ok {
		return nil
	}

	detail := fmt.Sprintf(
		"'%s' connected to %s:%d (known C2/reverse shell port)",
		evt.Event.Comm,
		evt.Event.DestIP,
		evt.Event.DestPort,
	)

	alert := newAlert(
		evt,
		"T1071 [Connection to suspicious port]",
		"warning",
		detail,
	)

	return &alert
}
