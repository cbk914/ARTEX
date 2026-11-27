package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/Autumn-27/artex/config"
)

const (
	jwtKeyFilename    = "jwt.key"
	authPassKey       = "auth.password_hash"
	authPwdVersionKey = "auth.password_version"
	jwtTTL            = 7 * 24 * time.Hour
	keyChars          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// The lower bound matches the setup page's frontend validation — validation that
	// lives only in the frontend is as good as none: hitting the API directly bypasses
	// it. The upper bound is bcrypt's hard limit: past 72 bytes GenerateFromPassword returns ErrPasswordTooLong; rejecting early beats a cryptic "password encryption failed".
	// Both apply to new passwords only (init, change-password); login never checks
	// length, so passwords set under the old 8-character minimum still log in.
	minPasswordRunes = 12
	maxPasswordBytes = 72

	pwdLimitTokenPrefix = "tok:"
)

// errDataSourceUnavailable is the uniform reply when a password-related read fails.
// These handlers must never mistake a failed read for "not set": authInit once let an
// unauthenticated request through on a database error, overwriting the admin password.
const errDataSourceUnavailable = "Data source temporarily unavailable, please retry later"

// pwdState values. The zero value is unread, which still accepts a valid token
// at version 0. unreadable means a startup read failed and every token is rejected.
const (
	pwdUnread int32 = iota
	pwdReady
	pwdUnreadable
)

// validatePassword returns an empty string when passing, otherwise a reason ready to show the user.
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("Password must be at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("Password must not exceed %d bytes", maxPasswordBytes)
	}
	return ""
}

// jwtLegacyBaseDir is the second legacy key location (the executable's directory,
// where releases before ARTEX_JWT_KEY_DIR wrote the key). A var so tests can point it
// at a temp dir.
var jwtLegacyBaseDir = config.BaseDir

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// ARTEX_JWT_KEY_DIR (the /app/keys volume in Docker) or the project base dir, NOT
// the browsable workspace root (dataDir) — the signing key must never be
// listable/downloadable via the file manager. When keyDir/jwt.key is missing, a key
// at dataDir/jwt.key, then at BaseDir()/jwt.key, is migrated (key preserved, so
// sessions stay valid) and the old file removed. Otherwise a random key is
// generated. An existing key file is never overwritten.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create jwt key dir: %w", err)
	}
	path := filepath.Join(keyDir, jwtKeyFilename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := migrateJWTKey(path, dataDir); err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if len(key) < 32 {
			return nil, fmt.Errorf("jwt key %s is shorter than 32 bytes; fix or remove it (it is never overwritten)", path)
		}
		return []byte(key), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read jwt key: %w", err)
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := writeNewJWTKey(path, buf); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] new JWT key written to %s", path)
	return buf, nil
}

// migrateJWTKey copies the first legacy key found (dataDir, then BaseDir) to dst
// and removes the old file. Candidates equal to dst are skipped.
func migrateJWTKey(dst, dataDir string) error {
	for _, src := range []string{
		filepath.Join(dataDir, jwtKeyFilename),
		filepath.Join(jwtLegacyBaseDir(), jwtKeyFilename),
	} {
		if samePath(src, dst) {
			continue
		}
		data, err := os.ReadFile(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Printf("[auth] cannot read legacy JWT key %s: %v", src, err)
			continue
		}
		if err := writeNewJWTKey(dst, data); err != nil {
			return fmt.Errorf("migrate jwt key from %s: %w", src, err)
		}
		if err := os.Remove(src); err != nil {
			log.Printf("[auth] JWT key copied to %s but the old file %s could not be removed: %v", dst, src, err)
		}
		log.Printf("[auth] JWT key migrated from %s to %s", src, dst)
		return nil
	}
	return nil
}

// writeNewJWTKey creates path with mode 0600, failing if it already exists.
func writeNewJWTKey(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func samePath(a, b string) bool {
	if absA, err := filepath.Abs(a); err == nil {
		a = absA
	}
	if absB, err := filepath.Abs(b); err == nil {
		b = absB
	}
	return a == b
}

// sessionClaims carries the password version the token was signed under.
// Two changes in the same second get different versions, so a cutoff based on
// the issued-at second cannot leave the older token valid.
type sessionClaims struct {
	Pwd *int64 `json:"pwd"`
	jwt.RegisteredClaims
}

// signJWT issues a 7-day HS256 token for user ARTEX at password version 0.
func signJWT(key []byte) (string, error) {
	return signJWTVersion(key, 0)
}

// signJWTVersion issues a 7-day HS256 token bound to a password version.
func signJWTVersion(key []byte, version int64) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{
		Pwd: &version,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "ARTEX",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        hex.EncodeToString(nonce[:]),
		},
	}).SignedString(key)
}

// parseSessionClaims applies the same token constraints for authorization and
// approver attribution. A missing pwd claim is distinct from version zero.
func parseSessionClaims(tokenStr string, key []byte) (*sessionClaims, bool) {
	claims := &sessionClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(*jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(), jwt.WithSubject("ARTEX"))
	return claims, err == nil && t.Valid && claims.Pwd != nil
}

// verifyJWT accepts only a current-version ARTEX session with all required claims.
func verifyJWT(tokenStr string, key []byte, version int64) bool {
	claims, ok := parseSessionClaims(tokenStr, key)
	return ok && version >= 0 && *claims.Pwd == version
}

// sessionOK reports whether token is still a session for the password version
// this process has loaded. A failed version read rejects every token until
// login reads the counter again.
func (s *Server) sessionOK(token string) bool {
	if s.pwdState.Load() == pwdUnreadable {
		return false
	}
	if !verifyJWT(token, s.jwtKey, s.pwdVersion.Load()) {
		return false
	}
	if s.revocations != nil {
		revoked, err := s.revocations.IsSessionRevoked(token)
		return err == nil && !revoked
	}
	return !s.revocationRequired
}

func (s *Server) passwordHashKey() string {
	if s.authHashKey != "" {
		return s.authHashKey
	}
	return authPassKey
}

func (s *Server) passwordVersionKey() string {
	if s.authVersionKey != "" {
		return s.authVersionKey
	}
	return authPwdVersionKey
}

// applyPasswordVersion records a version that was just committed or read.
// Concurrent rotations can finish their post-commit work out of order; an
// older completion must not resurrect sessions from the previous password.
func (s *Server) applyPasswordVersion(n int64) {
	for {
		current := s.pwdVersion.Load()
		if n <= current || s.pwdVersion.CompareAndSwap(current, n) {
			break
		}
	}
	s.pwdState.Store(pwdReady)
}

// jwtSubject returns the subject of a valid ARTEX session, and "" otherwise.
func jwtSubject(tokenStr string, key []byte) string {
	claims, ok := parseSessionClaims(tokenStr, key)
	if !ok {
		return ""
	}
	return claims.Subject
}

// approver is who a human decision is recorded for: the subject of the
// request's session token.
func (s *Server) approver(r *http.Request) string {
	tok := extractToken(r)
	if !s.sessionOK(tok) {
		return ""
	}
	return jwtSubject(tok, s.jwtKey)
}

// extractToken reads the JWT from Authorization: Bearer or the browser cookie.
// URL parameters are never session credentials: URLs can reach logs and history.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// cookieAuthenticated reports whether extractToken takes the session from the
// artex_token cookie. The browser attaches that cookie on its own, to requests
// a foreign page makes as well; a bearer token is put there by the caller.
func cookieAuthenticated(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	c, err := r.Cookie("artex_token")
	return err == nil && c.Value != ""
}

// sameOrigin reports whether the browser states that the request comes from a
// page of this server: Sec-Fetch-Site is same-origin, or Origin names the
// scheme, host and port the request was sent to. Scripts can set neither
// header. A request that carries neither is not same-origin.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	// The static console's local development server proxies HTTP requests and
	// connects to backend streams directly. Trust only its explicitly configured
	// loopback origin, which localBrowserDevOrigin validates against this host.
	if origin := r.Header.Get("Origin"); origin != "" &&
		origin == os.Getenv("ARTEX_BROWSER_DEV_ORIGIN") && localBrowserDevOrigin(origin, r.Host) {
		return true
	}
	o, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || o.Host == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return o.Scheme == scheme && hostWithPort(o.Host, scheme) == hostWithPort(r.Host, scheme)
}

// browserCookieSecure permits plain HTTP only on the local development host.
// A public Host is treated as HTTPS-facing even if a reverse proxy terminates
// TLS before forwarding to ARTEX. This fails closed for direct public HTTP.
func browserCookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host := strings.ToLower((&url.URL{Host: r.Host}).Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}

func setBrowserSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: "artex_token", Value: token, Path: "/",
		HttpOnly: true, Secure: browserCookieSecure(r), SameSite: http.SameSiteLaxMode,
		MaxAge: int(jwtTTL / time.Second),
	})
}

func clearBrowserSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "artex_token", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: browserCookieSecure(r), SameSite: http.SameSiteLaxMode,
	})
}

// Browser logins opt in to a server-owned HttpOnly cookie. Legacy API clients
// keep the JSON bearer response, so they do not have to adopt cookie auth.
func writeLoginSession(w http.ResponseWriter, r *http.Request, token string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("X-ARTEX-Browser-Session") != "1" {
		writeJSON(w, 200, map[string]any{"token": token})
		return
	}
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "browser session requires a same-origin request")
		return
	}
	setBrowserSessionCookie(w, r, token)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// hostWithPort returns host in lower case with its port, the scheme's default
// when host names none.
func hostWithPort(host, scheme string) string {
	u := url.URL{Host: host}
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// requireAuth wraps h with JWT validation.
// /api/auth/*, /api/health and /api/ready are exempt.
// A state-changing request whose session is the cookie must be same-origin
// (see sameOrigin), so that a foreign page cannot act with the operator's
// session. Requests that carry a bearer token, and GET and HEAD, are not checked.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" || p == "/api/ready" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "Unauthorized")
			return
		}
		if !s.sessionOK(tok) {
			writeErr(w, 401, "token is invalid or expired")
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if cookieAuthenticated(r) && !sameOrigin(r) {
				writeErr(w, 403, "cross-origin request refused: a cookie session can change state only from the console's own origin; send the token as Authorization: Bearer instead")
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// A read failure must answer 503, not initialized:false: on initialized:false the
// frontend ships the user to /setup to set a password (login/page.tsx); wrapping a
// database outage in a 200 pushes the user toward overwriting the existing password.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(s.passwordHashKey())
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// authSession lets the static browser UI check its HttpOnly cookie without
// exposing the token to JavaScript. A valid legacy script-written cookie is
// replaced with the server-owned flags during migration.
func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie("artex_token")
	if err != nil || cookie.Value == "" {
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	if !s.sessionOK(cookie.Value) {
		clearBrowserSessionCookie(w, r)
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	setBrowserSessionCookie(w, r, cookie.Value)
	writeJSON(w, 200, map[string]any{"authenticated": true})
}

// authMigrate exchanges a legacy localStorage bearer for a server-owned cookie.
// The browser removes its old copy regardless of this request's outcome.
func (s *Server) authMigrate(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) || r.Header.Get("X-ARTEX-Browser-Session") != "1" {
		writeErr(w, http.StatusForbidden, "browser session migration requires a same-origin request")
		return
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || !s.sessionOK(strings.TrimPrefix(h, "Bearer ")) {
		writeErr(w, http.StatusUnauthorized, "legacy session is invalid or expired")
		return
	}
	setBrowserSessionCookie(w, r, strings.TrimPrefix(h, "Bearer "))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// authLogout persists the token digest before clearing the browser cookie.
// A database outage fails closed so a copied bearer cannot silently survive.
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if !cookieAuthenticated(r) {
		writeErr(w, http.StatusUnauthorized, "browser session cookie required")
		return
	}
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "cross-origin cookie logout refused")
		return
	}
	cookie, _ := r.Cookie("artex_token")
	claims, valid := parseSessionClaims(cookie.Value, s.jwtKey)
	if !valid || !s.sessionOK(cookie.Value) {
		writeErr(w, http.StatusUnauthorized, "session is invalid or expired")
		return
	}
	if s.revocations == nil {
		writeErr(w, http.StatusServiceUnavailable, errDataSourceUnavailable)
		return
	}
	if err := s.revocations.RevokeSession(cookie.Value, claims.ExpiresAt.Time); err != nil {
		writeErr(w, http.StatusServiceUnavailable, errDataSourceUnavailable)
		return
	}
	clearBrowserSessionCookie(w, r)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// setupTokenOut is where the setup token is printed: the stderr of the process.
// It is a variable so that tests can capture it.
var setupTokenOut io.Writer = os.Stderr

// initSetupToken generates the one-time setup token when no admin password is set
// and prints it on the server console. Without it, anyone who can reach the port
// before the operator could claim the instance through POST /api/auth/init.
// The token goes to stderr directly, not through the standard logger: the log
// sink keeps every line for /api/logs and persists it.
func (s *Server) initSetupToken() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	var hash string
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		var ok bool
		hash, ok, err = s.m.pg.GetSetting(s.passwordHashKey())
		if err == nil {
			if ok && hash != "" {
				return
			}
			break
		}
		log.Printf("[auth] password lookup attempt %d/3: %v", attempt, err)
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
	}
	if err != nil {
		log.Printf("[auth] password lookup failed; not issuing a setup token: %v", err)
		return
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("[auth] generate setup token: %v", err)
	}
	token := hex.EncodeToString(buf)
	s.setupMu.Lock()
	s.setupToken = token
	s.setupMu.Unlock()
	fmt.Fprintln(setupTokenOut, time.Now().Format("2006/01/02 15:04:05"), "[auth] no admin password is set. Setup token for the /setup page:", token)
	log.Printf("[auth] no admin password is set. The setup token for the /setup page was printed on the server console (stderr); it is not kept in this log")
}

// loadPasswordVersion reads auth.password_version. A missing key leaves the
// version at zero, which accepts every valid token. A read that still fails
// after three tries rejects every token. Login calls this again when the
// state is unreadable, and stays closed if that read fails too.
func (s *Server) loadPasswordVersion() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	var raw string
	var ok bool
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		raw, ok, err = s.m.pg.GetSetting(s.passwordVersionKey())
		if err == nil {
			break
		}
		log.Printf("[auth] password version attempt %d/3: %v", attempt, err)
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
	}
	if err != nil {
		log.Printf("[auth] password version unreadable; rejecting sessions until login can read it: %v", err)
		s.pwdState.Store(pwdUnreadable)
		return
	}
	if !ok || raw == "" {
		s.pwdVersion.Store(0)
		s.pwdState.Store(pwdReady)
		return
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		log.Printf("[auth] password version %q is not a counter; rejecting sessions until login can read it", raw)
		s.pwdState.Store(pwdUnreadable)
		return
	}
	// Startup and explicit recovery use the database as the authority, including
	// when repairing an unreadable in-memory version.
	s.pwdVersion.Store(n)
	s.pwdState.Store(pwdReady)
}

// checkSetupToken compares got with the active setup token in constant time.
// It fails when no token is active.
func (s *Server) checkSetupToken(got string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.setupToken)) == 1
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
// Requires the setup token from the server log.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(s.passwordHashKey())
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "Password is already set")
		return
	}
	var req struct {
		Password   string `json:"password"`
		SetupToken string `json:"setup_token"`
	}
	if err := decode(w, r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "Password cannot be empty")
		return
	}
	// 403, not 401: the frontend treats any 401 as an expired session and redirects to /login.
	if !s.checkSetupToken(req.SetupToken) {
		writeErr(w, 403, "Invalid setup token. The server log prints it at startup while no password is set")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	// The hash and version commit in one transaction. ON CONFLICT DO NOTHING on the
	// hash keeps the first password: the GetSetting above is only a fast-fail path.
	// bcrypt runs tens of milliseconds, another request may set the password meanwhile, and the read check itself can fail under an outage.
	version, inserted, err := pg.InsertPassword(s.passwordHashKey(), string(hash), s.passwordVersionKey())
	if err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "Password is already set")
		return
	}
	s.setupMu.Lock()
	s.setupToken = ""
	s.setupMu.Unlock()
	s.applyPasswordVersion(version)
	tok, err := signJWTVersion(s.jwtKey, version)
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeLoginSession(w, r, tok)
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	// /api/auth/* bypasses requireAuth. This authenticated state change must
	// enforce the same cookie-origin rule here before reading or mutating state.
	if cookieAuthenticated(r) && !sameOrigin(r) {
		writeErr(w, 403, "cross-origin request refused: a cookie session can change state only from the console's own origin; send the token as Authorization: Bearer instead")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !s.sessionOK(extractToken(r)) {
		writeErr(w, 401, "Unauthorized")
		return
	}
	if wait := s.passwordChangeWait(r); wait > 0 {
		secs := int((wait + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, 429, fmt.Sprintf("Too many password change attempts, try again in %d seconds", secs))
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "New password cannot be empty")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(s.passwordHashKey())
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "Current password is wrong")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	// Hash and version commit together. A failed write returns 500 and leaves
	// the previous session valid. This response has no replacement token.
	version, err := pg.RotatePassword(s.passwordHashKey(), string(newHash), s.passwordVersionKey())
	if err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	s.passwordChangeReset(r)
	s.applyPasswordVersion(version)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// passwordChangeWait records one authenticated change-password attempt against
// the client IP and the session token. Either bucket can block; rotating the
// source address with a stolen token still hits the token bucket.
func (s *Server) passwordChangeWait(r *http.Request) time.Duration {
	if s.pwdLimit == nil {
		return 0
	}
	ip := clientIP(r, s.trustedProxies)
	tok := pwdLimitTokenPrefix + extractToken(r)
	return max(s.pwdLimit.allow(ip), s.pwdLimit.allow(tok))
}

func (s *Server) passwordChangeReset(r *http.Request) {
	if s.pwdLimit == nil {
		return
	}
	s.pwdLimit.reset(clientIP(r, s.trustedProxies))
	s.pwdLimit.reset(pwdLimitTokenPrefix + extractToken(r))
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	s.login(w, r, pg.GetAuthSnapshot)
}

// login is authLogin past the data-source check; getSnapshot is pg.GetAuthSnapshot,
// a parameter so tests can run it without PostgreSQL. Every attempt counts
// against the caller's IP (s.loginLimit, keyed by clientIP) and a successful
// one clears it. There is no per-account lockout and no password length check here.
func (s *Server) login(w http.ResponseWriter, r *http.Request, getSnapshot func(string, string) (string, bool, int64, error)) {
	ip := clientIP(r, s.trustedProxies)
	if wait := s.loginLimit.allow(ip); wait > 0 {
		secs := int((wait + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, 429, fmt.Sprintf("Too many login attempts, try again in %d seconds", secs))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if req.Username != "ARTEX" {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	hash, ok, version, err := getSnapshot(s.passwordHashKey(), s.passwordVersionKey())
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	s.loginLimit.reset(ip)
	if s.pwdState.Load() == pwdUnreadable {
		s.loadPasswordVersion()
	}
	if s.pwdState.Load() == pwdUnreadable {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	s.applyPasswordVersion(version)
	// Sign only the version read with this hash. A concurrent password rotation
	// may invalidate this token, but cannot make old credentials current.
	tok, err := signJWTVersion(s.jwtKey, version)
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeLoginSession(w, r, tok)
}
