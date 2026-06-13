package api

import (
	"fmt"
	"net/http"
	"time"
)

// stream is our server sent events endpoint The dashboard opens one
// EventSource here and receives live alerts as they arrive.
// we can use GET /alerts get the history alerts this is for the live view of things
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := s.hub.Subscribe()
	defer s.hub.Unsubscribe(client)

	// we open the response so the browser's EventSource fires onopen right away
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	// to keep it from being closed by proxies
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, open := <-client:
			if !open {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Name, ev.Data)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
