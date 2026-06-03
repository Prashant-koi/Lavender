package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/Prashant-koi/lavender/detection/internal/detection"
	nats "github.com/nats-io/nats.go"
)

func main() {
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:4222"
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	_, err = nc.Subscribe("telemetry.accepted.>", func(msg *nats.Msg) {
		alerts, err := detection.HandleCanonicalMessage(msg.Subject, msg.Data) // get the alerts
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
	select {}
}
