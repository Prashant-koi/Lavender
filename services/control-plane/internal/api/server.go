package api

import (
	"net/http"

	"github.com/Prashant-koi/lavender/control-plane/internal/store"
	"github.com/Prashant-koi/lavender/control-plane/internal/stream"
)

type Server struct {
	store *store.Store
	hub   *stream.Hub
}

func NewServer(store *store.Store, hub *stream.Hub) *Server {
	return &Server{store: store, hub: hub}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /alerts", s.listAlerts)
	mux.HandleFunc("PATCH /alerts/", s.updateAlertStatus)
	mux.HandleFunc("GET /api/stream", s.stream)

	return mux
}
