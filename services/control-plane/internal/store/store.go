package store

import (
	"context"
	"fmt"

	"github.com/Prashant-koi/lavender/control-plane/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AlertFilter struct {
	TenantID string
	AgentID  string
	Status   string
	Limit    int // how many rows to return
}

type Store struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func (s *Store) ListAlerts(ctx context.Context, filter AlertFilter) ([]models.Alert, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 200 {
		filter.Limit = 200 //min 50 max 200
	}

	rows, err := s.db.Query(ctx, `
			SELECT
				id,
				alert_id,
				tenant_id,
				agent_id,
				rule,
				severity,
				detail,
				event_type,
				event_pid,
				event_comm,
				observed_at,
				received_at,
				observed_at_unix_ms,
				received_at_unix_ms,
				status,
				created_at
			FROM alerts
			WHERE (&1 = '' OR tenant_id = $1)
			AND   (&2 = '' OR agent_id = $2)
			AND	  (&3 = '' OR status = $3)
			ORDER BY received_at DESC NULLS LAST, id DESC
			LIMIT $4
	`,
		filter.TenantID,
		filter.AgentID,
		filter.Status,
		filter.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query alerts error: %v", err)
	}
	defer rows.Close()

	alerts := make([]models.Alert, 0)
	for rows.Next() {
		var alert models.Alert
		if err := rows.Scan(
			&alert.ID,
			&alert.AlertID,
			&alert.TenantID,
			&alert.AgentID,
			&alert.Rule,
			&alert.Severity,
			&alert.Detail,
			&alert.EventType,
			&alert.EventPID,
			&alert.EventComm,
			&alert.ObservedAt,
			&alert.ReceivedAt,
			&alert.ObservedAtUnixMs,
			&alert.ReceivedAtUnixMs,
			&alert.Status,
			&alert.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan alert error: %v", err)
		}

		alerts = append(alerts, alert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alerts error: %v", err)
	}
	return alerts, nil
}

func (s *Store) UpdateAlertStatus(ctx context.Context, id int64, status string) (*models.Alert, error) {
	var alert models.Alert

	err := s.db.QueryRow(ctx, `
		UPDATE alerts
		SET status = $2
		WHERE id = $1
		RETURNING
			id,
			alert_id,
			tenant_id,
			agent_id,
			rule,
			severity,
			detail,
			event_type,
			event_pid,
			event_comm,
			observed_at,
			received_at,
			observed_at_unix_ms,
			received_at_unix_ms,
			status,
			created_at
			
	`,
		id,
		status,
	).Scan(
		&alert.ID,
		&alert.AlertID,
		&alert.TenantID,
		&alert.AgentID,
		&alert.Rule,
		&alert.Severity,
		&alert.Detail,
		&alert.EventType,
		&alert.EventPID,
		&alert.EventComm,
		&alert.ObservedAt,
		&alert.ReceivedAt,
		&alert.ObservedAtUnixMs,
		&alert.ReceivedAtUnixMs,
		&alert.Status,
		&alert.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("Update status error: %v", err)
	}

	return &alert, nil
}
