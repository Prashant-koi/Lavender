CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_pid INTEGER,
    event_comm TEXT,
    observed_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ,
    observed_at_unix_ms BIGINT NOT NULL,
    received_at_unix_ms BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- will add this later in control plane will have 4 differnt types (open/pending/resolved/dismissed) the menings of each are obvious
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- alert_id is the deterministic per id from detection, a unique index makes the insert idempotent
-- so a jetstream redelivery like when alert-writer
-- inserts then crashes before Ack can't store the same alert twice
CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_alert_id ON alerts (alert_id);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_received_at ON alerts (tenant_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_received_at ON alerts (agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status_received_at ON alerts (status, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_received_at ON alerts (rule, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_received_at ON alerts (severity, received_at DESC);