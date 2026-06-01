package main

import (
	"context"
	"log"
	"os"

	"github.com/Prashant-koi/lavender/telemetry-writer/internal/writer"
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

	// connect to db
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	store, err := writer.NewStore(ctx, databaseURL)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer store.Close()

	_, err = nc.Subscribe("telemetry.accepted.>", func(msg *nats.Msg) {
		row, err := writer.HandleCanonicalMessage(msg.Subject, msg.Data)
		if err != nil {
			log.Printf("writer error: %v", err)
			return
		}

		if row == nil {
			return
		}

		//inser to db
		if err := store.InsertCanonicalRow(ctx, row); err != nil {
			log.Printf("insert error: %v", err)
			return
		}

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

	log.Println("telemetry writer listening on telemetry.accepted.>")
	select {}
}
