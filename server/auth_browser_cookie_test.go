package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestBrowserLoginIssuesServerCookieWithoutTokenBody(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	getSnapshot := func(string, string) (string, bool, int64, error) {
		return string(hash), true, 0, nil
	}
	for _, tc := range []struct {
		name   string
		url    string
		origin string
		secure bool
	}{
		{name: "localhost HTTP", url: "http://localhost:8787/api/auth/login", origin: "http://localhost:8787"},
		{name: "public HTTPS", url: "https://console.example/api/auth/login", origin: "https://console.example", secure: true},
		{name: "public proxy HTTPS", url: "http://console.example/api/auth/login", origin: "http://console.example", secure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef"), loginLimit: newLoginLimiter(time.Now)}
			r := httptest.NewRequest(http.MethodPost, tc.url, strings.NewReader(`{"username":"ARTEX","password":"correct-horse-1"}`))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-ARTEX-Browser-Session", "1")
			w := httptest.NewRecorder()
			s.login(w, r, getSnapshot)
			if w.Code != http.StatusOK {
				t.Fatalf("login status=%d body=%s", w.Code, w.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if _, exposed := body["token"]; exposed {
				t.Fatal("browser login exposed the JWT in the response body")
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != "artex_token" {
				t.Fatalf("cookies=%v, want one artex_token", cookies)
			}
			c := cookies[0]
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != tc.secure || c.MaxAge != int(jwtTTL/time.Second) || !s.sessionOK(c.Value) {
				t.Fatalf("cookie flags or session invalid: HttpOnly=%v SameSite=%v Secure=%v MaxAge=%d", c.HttpOnly, c.SameSite, c.Secure, c.MaxAge)
			}
		})
	}

	// Existing API clients keep their bearer response and receive no browser cookie.
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef"), loginLimit: newLoginLimiter(time.Now)}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"ARTEX","password":"correct-horse-1"}`))
	w := httptest.NewRecorder()
	s.login(w, r, getSnapshot)
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || !s.sessionOK(body.Token) || len(w.Result().Cookies()) != 0 {
		t.Fatalf("API login status=%d token-valid=%v cookies=%v err=%v", w.Code, s.sessionOK(body.Token), w.Result().Cookies(), err)
	}
}

func TestBrowserSessionUpgradeLogoutAndLocalStreamCORS(t *testing.T) {
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	check := httptest.NewRequest(http.MethodGet, "http://localhost:8787/api/auth/session", nil)
	check.AddCookie(&http.Cookie{Name: "artex_token", Value: token})
	w := httptest.NewRecorder()
	s.authSession(w, check)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("session status=%d body=%s", w.Code, w.Body.String())
	}
	if cookies := w.Result().Cookies(); len(cookies) != 1 || !cookies[0].HttpOnly || !s.sessionOK(cookies[0].Value) {
		t.Fatalf("legacy cookie was not upgraded: %v", cookies)
	}
	migrate := httptest.NewRequest(http.MethodPost, "http://localhost:8787/api/auth/migrate", nil)
	migrate.Header.Set("Authorization", "Bearer "+token)
	migrate.Header.Set("X-ARTEX-Browser-Session", "1")
	migrate.Header.Set("Origin", "http://localhost:8787")
	w = httptest.NewRecorder()
	s.authMigrate(w, migrate)
	if cookies := w.Result().Cookies(); w.Code != 200 || len(cookies) != 1 || !cookies[0].HttpOnly || strings.Contains(w.Body.String(), token) {
		t.Fatalf("migration status=%d cookies=%v body=%s", w.Code, cookies, w.Body.String())
	}
	migrate.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.authMigrate(w, migrate)
	if w.Code != 403 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("foreign migration status=%d cookies=%v", w.Code, w.Result().Cookies())
	}
	foreign := httptest.NewRequest(http.MethodPost, "http://localhost:8787/api/auth/logout", nil)
	foreign.AddCookie(&http.Cookie{Name: "artex_token", Value: token})
	foreign.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.authLogout(w, foreign)
	if w.Code != 403 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("foreign logout status=%d cookies=%v", w.Code, w.Result().Cookies())
	}
	logout := httptest.NewRequest(http.MethodPost, "http://localhost:8787/api/auth/logout", nil)
	logout.AddCookie(&http.Cookie{Name: "artex_token", Value: token})
	logout.Header.Set("Origin", "http://localhost:8787")
	w = httptest.NewRecorder()
	s.authLogout(w, logout)
	if cookies := w.Result().Cookies(); w.Code != 200 || len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].HttpOnly {
		t.Fatalf("logout status=%d cookies=%v", w.Code, cookies)
	}

	t.Setenv("ARTEX_BROWSER_DEV_ORIGIN", "http://localhost:5173")
	devMutation := httptest.NewRequest(http.MethodPost, "http://localhost:8787/api/auth/logout", nil)
	devMutation.Header.Set("Origin", "http://localhost:5173")
	if !sameOrigin(devMutation) {
		t.Fatal("configured local console origin rejected for a backend mutation")
	}
	devMutation.Header.Set("Origin", "http://localhost:5174")
	if sameOrigin(devMutation) {
		t.Fatal("unconfigured local origin accepted for a backend mutation")
	}
	devMutation.Host = "console.example"
	devMutation.Header.Set("Origin", "http://localhost:5173")
	if sameOrigin(devMutation) {
		t.Fatal("local development origin accepted for a public backend")
	}
	h := cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		name, host, origin, wantOrigin, wantCredentials string
	}{
		{"dev stream", "localhost:8787", "http://localhost:5173", "http://localhost:5173", "true"},
		{"other local origin", "localhost:8787", "http://localhost:5174", "*", ""},
		{"public backend", "console.example", "http://localhost:5173", "*", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/api/logs/stream", nil)
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != tc.wantOrigin || w.Header().Get("Access-Control-Allow-Credentials") != tc.wantCredentials {
				t.Fatalf("CORS status=%d origin=%q credentials=%q", w.Code, w.Header().Get("Access-Control-Allow-Origin"), w.Header().Get("Access-Control-Allow-Credentials"))
			}
		})
	}
}
