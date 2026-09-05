package main

import (
	"log"
	"time"

	"github.com/Prashant-koi/lavender/ingest/internal/ingest"
	"github.com/Prashant-koi/lavender/services/platform/env"
	"github.com/Prashant-koi/lavender/services/platform/natsx"
	"github.com/Prashant-koi/lavender/services/platform/shutdown"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const protoContentType = "application/x-protobuf"

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

	// telemetry.raw.<tenant>.<agent_id> — all telemetry is protobuf now
	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		subject, payload, eventID, err := ingest.HandleProtoMessage(
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

		// republish to the canonical stream, carrying the proto content-type forward.
		// event_id doubles as the dedup msg id.
		out := &nats.Msg{
			Subject: subject,
			Data:    payload,
			Header: nats.Header{
				"content-type":       []string{protoContentType},
				jetstream.MsgIDHeader: []string{eventID},
			},
		}
		if _, err := js.PublishMsg(ctx, out); err != nil {
			log.Printf("republish failed of %s : %v", subject, err)
			msg.Nak()
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
