package main

import (
	"log"
	"time"

	"github.com/Prashant-koi/lavender/ingest/internal/ingest"
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

	// we will subscribe to every raw telemetry from our agents
	// telemetry.raw.<tenant>.<agent_id> for self reference
	_, err = nc.Subscribe("telemetry.raw.>", func(msg *nats.Msg) {

		// call the function that decodes the raw and makes it in form
		// of canonical event
		// the subject here is the acceptedSubj return in the HandleTransportMessage fucntion defn
		subject, payload, err := ingest.HandleTransportMessage(
			msg.Subject,
			msg.Data,
			func() int64 { return time.Now().UnixMilli() },
		)

		if err != nil {
			log.Printf("%v", err)
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
	<-ctx.Done()
}
