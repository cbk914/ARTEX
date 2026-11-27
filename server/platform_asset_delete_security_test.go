package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
)

func TestGlobalHostDeletionRequiresOperatorSession(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	host := fmt.Sprintf("synthetic-delete-%d.test", time.Now().UnixNano())
	child := "sub." + host
	_, err := s.m.pg.Exec(`INSERT INTO assets(type,domain,root_domain) VALUES ('root_domain',$1,$1),('subdomain',$2,$1)`, host, child)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM assets WHERE domain=$1 OR root_domain=$1`, host) })
	remaining := func() int {
		t.Helper()
		var count int
		if err := s.m.pg.QueryRow(`SELECT count(*) FROM assets WHERE domain=$1 OR root_domain=$1`, host).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	input := `{"host":"` + host + `"}`
	result, err := s.toolDeleteAssetsByHost().Call(agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 123}), []byte(input), nil)
	if err != nil || !result.IsError || remaining() != 2 {
		t.Fatalf("agent deleted global assets without operator approval: err=%v result=%+v remaining=%d", err, result, remaining())
	}
	if slices.Contains(platformToolKeys, "delete_assets_by_host") {
		t.Fatal("global deletion remains a default agent tool")
	}
	path := "/api/assets/by-host"
	if resp := request(http.MethodDelete, path, input); resp.Code != http.StatusBadRequest || remaining() != 2 {
		t.Fatalf("unconfirmed delete: %d %s remaining=%d", resp.Code, resp.Body.String(), remaining())
	}
	unauthorized := httptest.NewRequest(http.MethodDelete, path, strings.NewReader(`{"host":"`+host+`","confirm_host":"`+host+`"}`))
	unauthorized.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, unauthorized)
	if rec.Code != http.StatusUnauthorized || remaining() != 2 {
		t.Fatalf("unauthenticated delete: %d remaining=%d", rec.Code, remaining())
	}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	foreign := httptest.NewRequest(http.MethodDelete, path, strings.NewReader(`{"host":"`+host+`","confirm_host":"`+host+`"}`))
	foreign.Header.Set("Content-Type", "application/json")
	foreign.Header.Set("Cookie", "artex_token="+token)
	foreign.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, foreign)
	if rec.Code != http.StatusForbidden || remaining() != 2 {
		t.Fatalf("foreign-cookie delete: %d remaining=%d", rec.Code, remaining())
	}
	confirmed := `{"host":"` + host + `","confirm_host":"` + host + `"}`
	resp := request(http.MethodDelete, path, confirmed)
	if resp.Code != http.StatusOK || remaining() != 0 {
		t.Fatalf("operator-confirmed delete: %d %s remaining=%d", resp.Code, resp.Body.String(), remaining())
	}
}
