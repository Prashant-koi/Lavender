package host

import (
	"sync"
	"time"
)

// host liveness states
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
)

type State struct {
	TenantID       string `json:"tenant_id"`
	AgentID        string `json:"agent_id"`
	Hostname       string `json:"hostname"`
	Status         string `json:"status"` // StatusOnline or StatusOffline for now, can and prob will have more states
	LastSeenUnixMs int64  `json:"last_seen_unix_ms"`
}

type Registry struct {
	mu   sync.RWMutex
	host map[Key]State
}

type Key struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
}

func NewRegistry() *Registry {
	return &Registry{host: make(map[Key]State)}
}

func (r *Registry) Observe(tenant, agentID, hostname string, now time.Time) (State, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := Key{TenantID: tenant, AgentID: agentID}

	prev, existed := r.host[key]
	transitioned := !existed || prev.Status != StatusOnline // either new or was offline

	s := State{
		TenantID:       tenant,
		AgentID:        agentID,
		Hostname:       hostname,
		Status:         StatusOnline,
		LastSeenUnixMs: now.UnixMilli(),
	}

	r.host[key] = s

	return s, transitioned
}

func (r *Registry) Sweep(now time.Time, ttl time.Duration) []State {
	r.mu.Lock()
	defer r.mu.Unlock()

	var flipped []State
	cutoff := now.Add(-ttl).UnixMilli()

	for key, s := range r.host {
		if s.Status == StatusOnline && s.LastSeenUnixMs < cutoff {
			s.Status = StatusOffline
			r.host[key] = s
			flipped = append(flipped, s)
		}
	}

	return flipped
}

func (r *Registry) Snapshot() []State {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]State, 0, len(r.host))

	for _, s := range r.host {
		out = append(out, s)
	}

	return out
}
