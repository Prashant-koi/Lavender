package main

import (
	"encoding/json"
	"log"

	"github.com/Prashant-koi/lavender/services/platform/events"
	"github.com/Prashant-koi/lavender/alert-writer/internal/writer"
	"github.com/Prashant-koi/lavender/services/platform/env"
	"github.com/Prashant-koi/lavender/services/platform/natsx"
	"github.com/Prashant-koi/lavender/services/platform/postgres"
	"github.com/Prashant-koi/lavender/services/platform/shutdown"
	nats "github.com/nats-io/nats.go"
)

func main() {
	natsURL := env.Default("NATS_URL", "nats://127.0.0.1:4222")
	databaseURL, err := env.Required("DATABASE_URL")
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := shutdown.Context()
	defer stop()

	db, err := postgres.Connect(ctx, databaseURL)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer db.Close()

	nc, err := natsx.Connect(natsURL)
	if err != nil {
		log.Fatalf("failed to connect to nats: %v", err)
	}
	defer nc.Drain()

	sub, err := nc.Subscribe("alerts.>", func(msg *nats.Msg) {
		var alert events.AlertEvent
		if err := json.Unmarshal(msg.Data, &alert); err != nil {
			log.Printf("invalid alert payload on %s : %v", msg.Subject, err)
			return
		}

		if err := writer.InsertAlert(ctx, db, alert); err != nil {
			log.Printf("insert alert failed: %v", err)
			return
		}

		log.Printf("stored alert %s rule = %q severity = %s", alert.AlertID, alert.Rule, alert.Severity)
	})
	if err != nil {
		log.Fatalf("subscribe alerts: %v", err)
	}
	defer sub.Unsubscribe()

	log.Printf("alert-writer subscribed to alerts.>")

	<-ctx.Done()
	log.Printf("alert-writer shutting down")
}
