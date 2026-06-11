package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Prashant-koi/lavender/control-plane/internal/store"
)

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	// TODO need to make db pinger and check its health too

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	tenantID := query.Get("tenant_id")
	agentID := query.Get("agent_id")
	status := query.Get("status")
	limitRaw := query.Get("limit")

	limit := 50 //default min lim of rows

	if limitRaw != "" {
		parsedLimit, err := strconv.Atoi(limitRaw)
		if err != nil {
			http.Error(w, "failed parsing limit of rows", http.StatusBadRequest)
			return
		}
		if parsedLimit <= 0 {
			limit = 50
		} else if parsedLimit > 200 {
			limit = 200
		} else {
			limit = parsedLimit
		}
	}

	if status != "" {
		switch status {
		case "open", "acknowledged", "resolved", "dismissed":

		default:
			http.Error(w, "Invalid alert status", http.StatusBadRequest)
			return
		}
	}

	filter := store.AlertFilter{
		TenantID: tenantID,
		AgentID:  agentID,
		Status:   status,
		Limit:    limit,
	}

	alerts, err := s.store.ListAlerts(r.Context(), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		http.Error(w, "failed to encode response (alerts)", http.StatusInternalServerError)
		return
	}
}
