package main

import (
	"log"

	"github.com/Prashant-koi/lavender/services/platform/env"
	"github.com/Prashant-koi/lavender/services/platform/natsx"
	"github.com/Prashant-koi/lavender/services/platform/shutdown"
	"github.com/Prashant-koi/lavender/telemetry-writer/internal/writer"
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

	databaseURL, err := env.Required("DATABASE_URL")
	if err != nil {
		log.Fatal(err)
	}

	store, err := writer.NewStore(ctx, databaseURL)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer store.Close()

	js, err := natsx.JetStream(nc)
	if err != nil {
		log.Fatal(err)
	}

	canonicalStream, err := natsx.EnsureStream(ctx, js, natsx.TelemetryCanonicalStream)
	if err != nil {
		log.Fatal(err)
	}

	consumer, err := natsx.EnsureDurableConsumer(ctx, canonicalStream, "telemetry-writer")
	if err != nil {
		log.Fatal(err)
	}

	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		row, err := writer.HandleCanonicalMessage(msg.Subject(), msg.Data())
		if err != nil {
			log.Printf("writer error: %v", err)
			msg.Term()
			return
		}

		if row == nil {
			msg.Ack()
			return
		}

		//inser to db
		if err := store.InsertCanonicalRow(ctx, row); err != nil {
			log.Printf("insert error: %v", err)
			msg.Nak()
			return
		}

		msg.Ack()

		switch row.EventType {
		case "exec":
			log.Printf(
				"exec row agent = %s host = %s pid = %d ppid = %d comm = %s file = %s argv = %q",
				row.AgentID,
				row.Hostname,
				row.PID,
				row.PPID,
				row.Comm,
				row.Filename,
				row.Argv,
			)
		case "open":
			log.Printf(
				"open row agent = %s host = %s pid = %d comm = %s file = %s",
				row.AgentID,
				row.Hostname,
				row.PID,
				row.Comm,
				row.Filename,
			)
		case "connect":
			log.Printf(
				"connect row agent = %s host = %s pid = %d comm = %s dest = %s:%d af = %d",
				row.AgentID,
				row.Hostname,
				row.PID,
				row.Comm,
				row.DestIP,
				row.DestPort,
				row.AF,
			)
		}
	})
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Stop()

	log.Println("telemetry writer consuming durable 'telemetry-writer' on stream TELEMETRY_CANONICAL")
	<-ctx.Done()
}
