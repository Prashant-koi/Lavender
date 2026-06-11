package api

import (
	"net/http"

	"github.com/Prashant-koi/lavender/control-plane/internal/store"
)

type Server struct {
	store *store.Store
	mux   *http.ServeMux
}

func NewServer(store *store.Store) *Server {
	return &Server{store: store}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /alerts", s.listAlerts)
	mux.HandleFunc("PATCH /alerts/", s.updateAlertStatus)

	return mux
}
