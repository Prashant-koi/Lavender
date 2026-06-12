package main

import (
	"log"
	"time"

	"github.com/Prashant-koi/lavender/ingest/internal/ingest"
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

	// we consume the raw stream and publish into the canonical one,
	// so make sure both exist before any message moves
	rawStream, err := natsx.EnsureStream(ctx, js, natsx.TelemetryRawStream)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := natsx.EnsureStream(ctx, js, natsx.TelemetryCanonicalStream); err != nil {
		log.Fatal(err)
	}

	consumer, err := natsx.EnsureDurableConsumer(ctx, rawStream, "ingest")
	if err != nil {
		log.Fatal(err)
	}

	// telemetry.raw.<tenant>.<agent_id> for self reference
	cc, err := consumer.Consume(func(msg jetstream.Msg) {

		// call the function that decodes the raw and makes it in form
		// of canonical event
		// the subject here is the acceptedSubj return in the HandleTransportMessage fucntion defn
		subject, payload, eventID, err := ingest.HandleTransportMessage(
			msg.Subject(),
			msg.Data(),
			func() int64 { return time.Now().UnixMilli() },
		)

		if err != nil {
			// bad payloads will never get better, terminate so jetstream
			// does not redeliver them
			log.Printf("%v", err)
			msg.Term()
			return
		}

		// we will finally republish to the canonical stream, event_id doubles
		// as the dedup msg id so a redelivered raw message can't produce two
		// canonical events
		if _, err := js.Publish(ctx, subject, payload, jetstream.WithMsgID(eventID)); err != nil {
			log.Printf("republish failed of %s : %v", subject, err)
			msg.Nak() // transient failure, let jetstream redeliver
			return
		}

		msg.Ack()
		log.Printf("accepeted and republished %s => %s", msg.Subject(), subject)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Stop()

	log.Println("ingest service consuming durable 'ingest' on stream TELEMETRY_RAW")
	<-ctx.Done()
}
