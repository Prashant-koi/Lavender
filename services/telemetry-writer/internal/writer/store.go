package writer

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

// create the connection pool and ping
func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool error: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres error: %w", err)
	}

	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

// insert with insert types
func (s *Store) InsertCanonicalRow(ctx context.Context, row *CanonicalRow) error {
	switch row.EventType {
	case "exec":
		return s.insertExec(ctx, row)
	case "open":
		return s.insertOpen(ctx, row)
	case "connect":
		return s.insertConnect(ctx, row)
	default:
		return nil
	}
}

func (s *Store) insertExec(ctx context.Context, row *CanonicalRow) error {
	_, err := s.pool.Exec(ctx, `
  		INSERT INTO exec_events (
  			agent_id,
  			tenant_id,
  			hostname,
  			observed_at,
  			received_at,
  			observed_at_unix_ms,
  			received_at_unix_ms,
  			pid,
  			ppid,
  			uid,
  			comm,
  			filename,
  			argv
  		)
  		VALUES (
  			$1,
  			$2,
  			$3,
  			to_timestamp($4::double precision / 1000.0),
  			to_timestamp($5::double precision / 1000.0),
  			$4,
  			$5,
  			$6,
  			$7,
  			$8,
  			$9,
  			$10,
  			$11
  		)
  	`,
		row.AgentID,
		row.TenantID,
		row.Hostname,
		row.ObservedAtUnixMs,
		row.ReceivedAtUnixMs,
		row.PID,
		row.PPID,
		row.UID,
		row.Comm,
		row.Filename,
		row.Argv,
	)

	if err != nil {
		return fmt.Errorf("insert exec event: %w", err)
	}

	return nil
}

func (s *Store) insertOpen(ctx context.Context, row *CanonicalRow) error {
	_, err := s.pool.Exec(ctx, `
  		INSERT INTO open_events (
  			agent_id,
  			tenant_id,
  			hostname,
  			observed_at,
  			received_at,
  			observed_at_unix_ms,
  			received_at_unix_ms,
  			pid,
  			comm,
  			filename
  		)
  		VALUES (
  			$1,
  			$2,
  			$3,
  			to_timestamp($4::double precision / 1000.0),
  			to_timestamp($5::double precision / 1000.0),
  			$4,
  			$5,
  			$6,
  			$7,
  			$8
  		)
  	`,
		row.AgentID,
		row.TenantID,
		row.Hostname,
		row.ObservedAtUnixMs,
		row.ReceivedAtUnixMs,
		row.PID,
		row.Comm,
		row.Filename,
	)

	if err != nil {
		return fmt.Errorf("insert open event: %w", err)
	}

	return nil
}

func (s *Store) insertConnect(ctx context.Context, row *CanonicalRow) error {
	_, err := s.pool.Exec(ctx, `
  		INSERT INTO connect_events (
  			agent_id,
  			tenant_id,
  			hostname,
  			observed_at,
  			received_at,
  			observed_at_unix_ms,
  			received_at_unix_ms,
  			pid,
  			uid,
  			comm,
  			dest_ip,
  			dest_port,
  			af
  		)
  		VALUES (
  			$1,
  			$2,
  			$3,
  			to_timestamp($4::double precision / 1000.0),
  			to_timestamp($5::double precision / 1000.0),
  			$4,
  			$5,
  			$6,
  			$7,
  			$8,
  			$9,
  			$10,
  			$11
  		)
  	`,
		row.AgentID,
		row.TenantID,
		row.Hostname,
		row.ObservedAtUnixMs,
		row.ReceivedAtUnixMs,
		row.PID,
		row.UID,
		row.Comm,
		row.DestIP,
		row.DestPort,
		row.AF,
	)

	if err != nil {
		return fmt.Errorf("insert connect event: %w", err)
	}

	return nil
}
