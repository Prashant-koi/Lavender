package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/Prashant-koi/lavender/detection/internal/detection"
	"github.com/Prashant-koi/lavender/services/platform/env"
	"github.com/Prashant-koi/lavender/services/platform/natsx"
	"github.com/Prashant-koi/lavender/services/platform/shutdown"
	nats "github.com/nats-io/nats.go"
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

	detector := detection.NewDetector()

	_, err = nc.Subscribe("telemetry.accepted.>", func(msg *nats.Msg) {
		alerts, err := detector.HandleCanonicalMessage(msg.Subject, msg.Data) // get the alerts
		if err != nil {
			log.Printf("detection error: %v", err)
			return
		}

		for _, alert := range alerts {
			payload, err := json.Marshal(alert)
			if err != nil {
				log.Printf("alert marshal error: %v", err)
				continue
			}

			subject := detection.AlertSubject(alert)
			if err := nc.Publish(subject, payload); err != nil {
				log.Printf("alert publish failed on %s: %v", subject, err)
				continue
			}
			if err := nc.FlushTimeout(2 * time.Second); err != nil {
				log.Printf("alert flush failed on %s: %v", subject, err)
				continue
			}

			log.Printf("published alert %s rule = %q pid = %d comm = %s", subject, alert.Rule, alert.PID, alert.Comm)
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("detection service listening on telemetry.accepted.>")
	<-ctx.Done()
}
