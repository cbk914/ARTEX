package db

import (
	"context"
	"crypto/sha256"
	"time"
)

const sessionRevocationDBTimeout = 5 * time.Second

// IsSessionRevoked checks the shared database on every authenticated request.
// Callers must fail closed if the database cannot answer.
func (d *DB) IsSessionRevoked(token string) (bool, error) {
	hash := sha256.Sum256([]byte(token))
	ctx, cancel := context.WithTimeout(context.Background(), sessionRevocationDBTimeout)
	defer cancel()
	var found bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM auth_session_revocations WHERE token_sha256=$1)`, hash[:]).Scan(&found)
	return found, err
}

// RevokeSession records the token digest before the browser cookie is cleared.
// The same row also covers a copy previously used as an API bearer.
func (d *DB) RevokeSession(token string, expiry time.Time) error {
	hash := sha256.Sum256([]byte(token))
	ctx, cancel := context.WithTimeout(context.Background(), sessionRevocationDBTimeout)
	defer cancel()
	_, err := d.ExecContext(ctx, `INSERT INTO auth_session_revocations(token_sha256, expires_at)
VALUES ($1, $2) ON CONFLICT (token_sha256) DO NOTHING`, hash[:], expiry)
	if err != nil {
		return err
	}
	_, _ = d.ExecContext(ctx, `DELETE FROM auth_session_revocations WHERE expires_at < now()`)
	return nil
}

var _ interface {
	IsSessionRevoked(string) (bool, error)
	RevokeSession(string, time.Time) error
} = (*DB)(nil)
