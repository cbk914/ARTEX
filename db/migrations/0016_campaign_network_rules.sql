-- Operator decisions for a future broker-owned egress gateway. Asset and
-- task_scope rows must never be copied into this table as authorization.
-- Keeping decisions and revocations append-only preserves their provenance.
CREATE TABLE IF NOT EXISTS campaign_network_rules (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    target_kind TEXT NOT NULL CHECK (target_kind IN ('hostname', 'ip', 'cidr')),
    target_value TEXT NOT NULL CHECK (length(target_value) BETWEEN 1 AND 253),
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port_start INTEGER NOT NULL CHECK (port_start BETWEEN 1 AND 65535),
    port_end INTEGER NOT NULL CHECK (port_end BETWEEN 1 AND 65535),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (port_start <= port_end),
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS campaign_network_rules_task_idx
    ON campaign_network_rules (task_id, id);

CREATE TABLE IF NOT EXISTS campaign_network_rule_revocations (
    rule_id BIGINT PRIMARY KEY REFERENCES campaign_network_rules(id),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 128),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
