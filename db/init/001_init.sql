CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS exec_events (
    id BIGSERIAL,
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    observed_at_unix_ms BIGINT NOT NULL,
    received_at_unix_ms BIGINT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    comm TEXT NOT NULL,
    filename TEXT NOT NULL,
    argv TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, received_at)
);

CREATE TABLE IF NOT EXISTS open_events (
    id BIGSERIAL,
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    observed_at_unix_ms BIGINT NOT NULL,
    received_at_unix_ms BIGINT NOT NULL,
    pid INTEGER NOT NULL,
    comm TEXT NOT NULL,
    filename TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, received_at)
);

CREATE TABLE IF NOT EXISTS connect_events (
    id BIGSERIAL,
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    observed_at_unix_ms BIGINT NOT NULL,
    received_at_unix_ms BIGINT NOT NULL,
    pid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    comm TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    af INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, received_at)
);

-- create hypertable for the events
SELECT create_hypertable('exec_events', 'received_at', if_not_exists => TRUE);
SELECT create_hypertable('open_events', 'received_at', if_not_exists => TRUE);
SELECT create_hypertable('connect_events', 'received_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_exec_events_tenant_received ON exec_events (tenant_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_open_events_tenant_received ON open_events (tenant_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_connect_events_tenant_received ON connect_events (tenant_id, received_at DESC);