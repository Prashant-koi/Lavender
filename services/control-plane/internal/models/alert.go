package models

import "time"

//shared alert struct

type Alert struct {
	ID               int64      `json:"id"`
	AlertID          string     `json:"alert_id"`
	TenantID         string     `json:"tenant_id"`
	AgentID          string     `json:"agent_id"`
	Rule             string     `json:"rule"`
	Severity         string     `json:"severity"`
	Detail           string     `json:"detail"`
	EventType        string     `json:"event_type"`
	EventPID         *int       `json:"event_pid"` // these are pointers since they CAN be NULL (easier to represnt)
	EventComm        *string    `json:"event_comm"`
	ObservedAt       *time.Time `json:"observed_at"`
	ReceivedAt       *time.Time `json:"received_at"`
	ObservedAtUnixMs int64      `json:"observed_at_unix_ms"`
	ReceivedAtUnixMs int64      `json:"received_at_unix_ms"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type AlertStatusUpdate struct {
	Status string `json:"status"`
}
