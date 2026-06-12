package main

import (
	"encoding/json"
	"log"

	"github.com/Prashant-koi/lavender/detection/internal/detection"
	"github.com/Prashant-koi/lavender/services/platform/env"
	"github.com/Prashant-koi/lavender/services/platform/natsx"
	"github.com/Prashant-koi/lavender/services/platform/shutdown"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	natsURL := env.Default("NATS_URL", "nats://127.0.0.1:4222")

	nc, err := natsx.Connect(natsURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Drain()

	ctx, stop := shutdown.Context()
	defer stop()

	js, err := natsx.JetStream(nc)
	if err != nil {
		log.Fatal(err)
	}

	// we read canonical events and publish alerts, so ensure both streams
	canonicalStream, err := natsx.EnsureStream(ctx, js, natsx.TelemetryCanonicalStream)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := natsx.EnsureStream(ctx, js, natsx.AlertsStream); err != nil {
		log.Fatal(err)
	}

	consumer, err := natsx.EnsureDurableConsumer(ctx, canonicalStream, "detection")
	if err != nil {
		log.Fatal(err)
	}

	detector := detection.NewDetector()

	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		alerts, err := detector.HandleCanonicalMessage(msg.Subject(), msg.Data()) // get the alerts
		if err != nil {
			// invalid canonical json
			log.Printf("detection error: %v", err)
			msg.Term()
			return
		}

		for _, alert := range alerts {
			payload, err := json.Marshal(alert)
			if err != nil {
				log.Printf("alert marshal error: %v", err)
				continue
			}

			// alert_id is deterministic per event_id, rule so if this canonical gets redelivered the dedup will shwlalo repeat publish
			subject := detection.AlertSubject(alert)
			if _, err := js.Publish(ctx, subject, payload, jetstream.WithMsgID(alert.AlertID)); err != nil {
				log.Printf("alert publish failed on %s: %v", subject, err)
				msg.Nak() // retry canonical
				return
			}

			log.Printf("published alert %s rule = %q pid = %d comm = %s", subject, alert.Rule, alert.PID, alert.Comm)
		}

		msg.Ack()
	})
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Stop()

	log.Println("detection service consuming durable 'detection' on stream TELEMETRY_CANONICAL")
	<-ctx.Done()
}
