package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/Prashant-koi/lavender/ingest/internal/events"
	"github.com/Prashant-koi/lavender/ingest/internal/ingest"
	nats "github.com/nats-io/nats.go"
)

func main() {
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:4222"
	}

	// connect
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	// we will subscribe to every raw telemetry from our agents
	// telemetry.raw.<tenant>.<agent_id> for self reference
	_, err = nc.Subscribe("telemetry.raw.>", func(msg *nats.Msg) {
		// decode
		var raw events.AgentTelemetryEvent
		if err := json.Unmarshal(msg.Data, &raw); err != nil {
			log.Printf("invalid json on %s : %v", msg.Subject, err)
			return
		}

		// validate the required fileds
		if err := ingest.ValidateTransportEvents(raw); err != nil {
			log.Printf(" couldn't validate on %s : %v", msg.Subject, err)
			return
		}

		// we will now conver the raw transport events
		//  into the canonical backend event

		canonical := events.CanonicalEvent{
			SchemaVersion:    raw.SchemaVersion,
			AgentID:          raw.AgentID,
			TenantID:         raw.TenantID,
			Host:             raw.Host,
			ObservedAtUnixMs: raw.ObservedAtUnixMs,
			ReceivedAtUnixMs: time.Now().UnixMilli(),
			Event:            raw.Event,
		}

		subject := ingest.CanonicalSubject(raw)

		payload, err := json.Marshal(canonical)
		if err != nil {
			log.Printf("Marshall of Canonical failed: %v", err)
			return
		}

		// we will finally republished to our internal stream
		if err := nc.Publish(subject, payload); err != nil {
			log.Printf("republish failed of %s : %v", subject, err)
			return
		}

		log.Printf("accepeted and republished %s => %s", msg.Subject, subject)
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("ingest service listening on telemetry.raw.>")
	<-context.Background().Done()
}
