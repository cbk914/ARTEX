package db

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestSessionRevocationPersistsWithoutStoringBearer(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	token := "synthetic-session-" + time.Now().UTC().Format(time.RFC3339Nano)
	hash := sha256.Sum256([]byte(token))
	defer func() { _, _ = d.Exec(`DELETE FROM auth_session_revocations WHERE token_sha256=$1`, hash[:]) }()
	if revoked, err := d.IsSessionRevoked(token); err != nil || revoked {
		t.Fatalf("new session revoked=%v err=%v", revoked, err)
	}
	if err := d.RevokeSession(token, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if revoked, err := other.IsSessionRevoked(token); err != nil || !revoked {
		t.Fatalf("revocation missing across connections: revoked=%v err=%v", revoked, err)
	}
	var stored string
	if err := other.QueryRow(`SELECT encode(token_sha256, 'hex') FROM auth_session_revocations WHERE token_sha256=$1`, hash[:]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != hex.EncodeToString(hash[:]) || strings.Contains(stored, token) {
		t.Fatal("stored token is not its SHA-256 digest")
	}
}
