package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Prashant-koi/lavender/control-plane/internal/models"
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

	if status != "" && !isValidAlertStatus(status) {
		http.Error(w, "Invalid alert status", http.StatusBadRequest)
		return
	}

	filter := store.AlertFilter{
		TenantID: tenantID,
		AgentID:  agentID,
		Status:   status,
		Limit:    limit,
	}

	alerts, err := s.store.ListAlerts(r.Context(), filter)
	if err != nil {
		log.Printf("list alerts: %v", err)
		http.Error(w, "failed to list alerts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		log.Printf("encode alerts response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (s *Server) updateAlertStatus(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, "/alerts/") || !strings.HasSuffix(path, "/status") {
		http.Error(w, "invalid alert status path", http.StatusBadRequest)
		return
	}

	idRaw := strings.TrimPrefix(path, "/alerts/")
	idRaw = strings.TrimSuffix(idRaw, "/status")
	idRaw = strings.TrimSuffix(idRaw, "/")

	id, err := strconv.ParseInt(idRaw, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid alert id", http.StatusBadRequest)
		return
	}

	var update models.AlertStatusUpdate

	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !isValidAlertStatus(update.Status) {
		http.Error(w, "Invalid alert status", http.StatusBadRequest)
		return
	}

	alert, err := s.store.UpdateAlertStatus(r.Context(), id, update.Status)
	if err != nil {
		log.Printf("update alert status: %v", err)
		http.Error(w, "failed to update alert status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(alert); err != nil {
		log.Printf("encode alert response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func isValidAlertStatus(status string) bool {
	if status == "" {
		return false
	}

	switch status {
	case "open", "acknowledged", "resolved", "dismissed":
		return true
	default:
		return false
	}

}
