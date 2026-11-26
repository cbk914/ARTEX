package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A password rotation after the old hash is read must never mint a session
// carrying the new version for the old password.
func TestLoginCannotSignOldPasswordAtNewVersion(t *testing.T) {
	oldHash, err := bcrypt.GenerateFromPassword([]byte("old-password-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef"), loginLimit: newLoginLimiter(time.Now)}
	s.applyPasswordVersion(1)
	hashRead := make(chan struct{})
	rotated := make(chan struct{})
	getSnapshot := func(hashKey, versionKey string) (string, bool, int64, error) {
		if hashKey != authPassKey || versionKey != authPwdVersionKey {
			t.Fatalf("unexpected setting keys %q, %q", hashKey, versionKey)
		}
		close(hashRead)
		<-rotated
		return string(oldHash), true, 1, nil
	}
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.login(w, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"ARTEX","password":"old-password-1"}`)), getSnapshot)
	}()
	<-hashRead
	s.applyPasswordVersion(2)
	close(rotated)
	<-done
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if verifyJWT(response.Token, s.jwtKey, 2) {
		t.Fatal("old password minted a current-version session after rotation")
	}
}

func TestPasswordVersionDoesNotRegressWhenRotationsFinishOutOfOrder(t *testing.T) {
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef")}
	s.applyPasswordVersion(1)
	s.applyPasswordVersion(3)
	s.applyPasswordVersion(2)
	if got := s.pwdVersion.Load(); got != 3 {
		t.Fatalf("password version regressed to %d", got)
	}
}
