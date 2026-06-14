package api

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	hosts := s.registry.Snapshot()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(hosts); err != nil {
		log.Printf("encode list agents resposne: %v", err)
		http.Error(w, "failed to list agents", http.StatusInternalServerError)
		return
	}
}
