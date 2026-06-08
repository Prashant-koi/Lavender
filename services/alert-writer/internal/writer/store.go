package writer

import (
	"context"

	"github.com/Prashant-koi/lavender/alert-writer/internal/events"
	"github.com/jackc/pgx/v5/pgxpool"
)

func InsertAlert(ctx context.Context, db *pgxpool.Pool, alert events.AlertEvent) error {
	_, err := db.Exec(ctx, `
		INSERT INTO alerts (
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
			received_at_unix_ms
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9,
			CASE WHEN $10::bigint = 0 THEN NULL ELSE to_timestamp($10::double precision / 1000.0) END,
			CASE WHEN $11::bigint = 0 THEN NULL ELSE to_timestamp($11::double precision / 1000.0) END,
			$10,
			$11
		)
	`,
		alert.AlertID,
		alert.TenantID,
		alert.AgentID,
		alert.Rule,
		alert.Severity,
		alert.Detail,
		alert.EventType,
		alert.EventPID,
		alert.EventComm,
		alert.ObservedAtUnixMs,
		alert.ReceivedAtUnixMs,
	)

	return err
}
