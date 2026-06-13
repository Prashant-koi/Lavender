package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Prashant-koi/lavender/control-plane/internal/api"
	"github.com/Prashant-koi/lavender/control-plane/internal/store"
	"github.com/Prashant-koi/lavender/control-plane/internal/stream"
	"github.com/Prashant-koi/lavender/services/platform/env"
	"github.com/Prashant-koi/lavender/services/platform/events"
	"github.com/Prashant-koi/lavender/services/platform/natsx"
	"github.com/Prashant-koi/lavender/services/platform/postgres"
	"github.com/Prashant-koi/lavender/services/platform/shutdown"
	nats "github.com/nats-io/nats.go"
)

func main() {
	databaseURL, err := env.Required("DATABASE_URL")
	if err != nil {
		log.Fatal(err)
	}
	natsURL := env.Default("NATS_URL", "nats://127.0.0.1:4222")

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

	hub := stream.NewHub()

	// here the control-plane consumes alerts to push them to
	// connected dashboards over SSE our alert writer service  is still the sole persister
	// basically aslert-writer service is mainly for the persistance of alerts and records
	// and storing them in db and this is for the live events to the dashbaord
	alertSub, err := nc.Subscribe("alerts.>", func(msg *nats.Msg) {
		var alert events.AlertEvent
		if err := json.Unmarshal(msg.Data, &alert); err != nil {
			log.Printf("live feed: skipping invalid alert on %s: %v", msg.Subject, err)
			return
		}
		hub.Broadcast(stream.Event{Name: "alert", Data: msg.Data})
	})
	if err != nil {
		log.Fatalf("subscribe alerts: %v", err)
	}
	defer alertSub.Unsubscribe()

	httpAddr := env.Default("HTTP_ADDR", ":8080")
	alertStore := store.New(db)
	apiServer := api.NewServer(alertStore, hub)

	server := &http.Server{
		Addr:              httpAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	go func() {
		log.Printf("control-plane listening on %s", httpAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("control-plane http server: %v", err)
		}
	}()

	log.Printf("control-plane live alert feed subscribed to alerts.>")

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("control-plane http shutdown: %v", err)
	}
}
