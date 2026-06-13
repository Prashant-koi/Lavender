package writer

import (
	"context"

	"github.com/Prashant-koi/lavender/services/platform/events"
	"github.com/jackc/pgx/v5/pgxpool"
)

func InsertAlert(ctx context.Context, db *pgxpool.Pool, alert events.AlertEvent) error {
	tenantID := "unknown"
	if alert.TenantID != nil && *alert.TenantID != "" {
		tenantID = *alert.TenantID
	}

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
		ON CONFLICT (alert_id) DO NOTHING
	`,
		alert.AlertID,
		tenantID,
		alert.AgentID,
		alert.Rule,
		alert.Severity,
		alert.Detail,
		alert.EventType,
		alert.PID,
		alert.Comm,
		alert.ObservedAtUnixMs,
		alert.ReceivedAtUnixMs,
	)

	return err
}
