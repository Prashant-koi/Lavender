package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/Prashant-koi/lavender/control-plane/internal/api"
	"github.com/Prashant-koi/lavender/control-plane/internal/store"
	"github.com/Prashant-koi/lavender/services/platform/env"
	"github.com/Prashant-koi/lavender/services/platform/postgres"
	"github.com/Prashant-koi/lavender/services/platform/shutdown"
)

func main() {
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

	httpAddr := env.Default("HTTP_ADDR", ":8080")
	alertStore := store.New(db)
	apiServer := api.NewServer(alertStore)

	server := &http.Server{
		Addr:              httpAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("control-plane listening on %s", httpAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("control-plane http server: %v", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("control-plane http shutdown: %v", err)
	}
}
