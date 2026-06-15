package api

import (
	"net/http"

	"github.com/Prashant-koi/lavender/control-plane/internal/host"
	"github.com/Prashant-koi/lavender/control-plane/internal/store"
	"github.com/Prashant-koi/lavender/control-plane/internal/stream"
)

type Server struct {
	store    *store.Store
	hub      *stream.Hub
	registry *host.Registry
	webDir   string // built dashboard to serve; empty = API only
}

func NewServer(store *store.Store, hub *stream.Hub, registry *host.Registry, webDir string) *Server {
	return &Server{store: store, hub: hub, registry: registry, webDir: webDir}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /alerts", s.listAlerts)
	mux.HandleFunc("PATCH /alerts/", s.updateAlertStatus)
	mux.HandleFunc("GET /api/stream", s.stream)
	mux.HandleFunc("GET /agents", s.listAgents)

	// In production the control-plane also serves the built dashboard
	// same-origin. Locally WEB_DIR is unset and the Vite dev server proxies the
	// API here instead, so we register no catch-all.
	if s.webDir != "" {
		mux.HandleFunc("GET /", spaFileServer(s.webDir))
	}

	return mux
}
