package main

import (
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

	_, err = nc.Subscribe("telemetry.accepted.>", func(msg *nats.Msg) {
		row, err := writer.HandleCanonicalMessage(msg.Subject, msg.Data)
		if err != nil {
			log.Printf("writer error: %v", err)
			return
		}

		if row == nil {
			return
		}

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
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("telemetry writer listening on telemetry.accepted.>")
	select {}
}
