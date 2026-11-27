-- Store only a digest of a revoked JWT. An expired entry is removed on the
-- next logout; the expiry index supports later scheduled retention cleanup.
CREATE TABLE IF NOT EXISTS auth_session_revocations (
    token_sha256 BYTEA PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_session_revocations_expiry_idx
    ON auth_session_revocations (expires_at);
