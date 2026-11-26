package server

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSessionJWTRejectsUnsupportedClaimsAndAlgorithms(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	valid, err := signJWTVersion(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(valid, key, 0) || jwtSubject(valid, key) != "ARTEX" {
		t.Fatal("a normal current session must remain valid")
	}

	exp := time.Now().Add(time.Hour).Unix()
	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
		claims jwt.MapClaims
	}{
		{"other HMAC algorithm", jwt.SigningMethodHS384, jwt.MapClaims{"sub": "ARTEX", "exp": exp, "pwd": 0}},
		{"missing expiration", jwt.SigningMethodHS256, jwt.MapClaims{"sub": "ARTEX", "pwd": 0}},
		{"wrong subject", jwt.SigningMethodHS256, jwt.MapClaims{"sub": "other", "exp": exp, "pwd": 0}},
		{"missing subject", jwt.SigningMethodHS256, jwt.MapClaims{"exp": exp, "pwd": 0}},
		{"missing password version", jwt.SigningMethodHS256, jwt.MapClaims{"sub": "ARTEX", "exp": exp}},
		{"malformed expiration", jwt.SigningMethodHS256, jwt.MapClaims{"sub": "ARTEX", "exp": "later", "pwd": 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := jwt.NewWithClaims(tc.method, tc.claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			if verifyJWT(token, key, 0) {
				t.Fatal("session validator accepted unsupported token")
			}
			if jwtSubject(token, key) != "" {
				t.Fatal("subject helper accepted unsupported token")
			}
		})
	}
}
