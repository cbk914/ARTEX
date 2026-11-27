package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNetworkDecisionOperatorRoutesRemainStaged(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	owner, err := s.m.CreateTask("synthetic network approval", "local only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.m.CreateTask("synthetic other campaign", "local only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ownerID, _ := strconv.ParseInt(owner.ID, 10, 64)
	otherID, _ := strconv.ParseInt(other.ID, 10, 64)
	t.Cleanup(func() {
		_, _ = s.m.pg.Exec(`DELETE FROM campaign_network_rule_revocations WHERE rule_id IN (SELECT id FROM campaign_network_rules WHERE task_id IN ($1,$2))`, ownerID, otherID)
		_, _ = s.m.pg.Exec(`DELETE FROM campaign_network_rules WHERE task_id IN ($1,$2)`, ownerID, otherID)
		_ = s.m.pg.DeleteTask(ownerID)
		_ = s.m.pg.DeleteTask(otherID)
	})
	base := "/api/tasks/" + owner.ID + "/network-decisions"
	if resp := request(http.MethodGet, base, ""); resp.Code != 200 || !strings.Contains(resp.Body.String(), `"enforced":false`) {
		t.Fatalf("staged decision list: %d %s", resp.Code, resp.Body.String())
	}
	for _, body := range []string{
		`{"effect":"allow","target_kind":"hostname","target_value":"target.test","protocol":"tcp","port_start":443,"port_end":443,"allow_direct":true,"expires_at":"` + time.Now().Add(time.Hour).Format(time.RFC3339) + `","reason":"operator-reviewed"}`,
		`{"unknown":"field"}`,
		`{} {}`,
		strings.Repeat("a", networkDecisionBodyLimit+1),
	} {
		resp := request(http.MethodPost, base, body)
		if resp.Code != http.StatusBadRequest && resp.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("invalid approval accepted: %d %s", resp.Code, resp.Body.String())
		}
	}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRequest(http.MethodPost, base, strings.NewReader(`{}`))
	unauthorized.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, unauthorized)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated approval: %d", rec.Code)
	}
	foreign := httptest.NewRequest(http.MethodPost, base, strings.NewReader(`{}`))
	foreign.Header.Set("Content-Type", "application/json")
	foreign.Header.Set("Cookie", "artex_token="+token)
	foreign.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, foreign)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin cookie approval: %d", rec.Code)
	}
	approval := func(kind, value string, direct bool) int64 {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"effect": "allow", "target_kind": kind, "target_value": value,
			"protocol": "tcp", "port_start": 443, "port_end": 443,
			"allow_direct": direct, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"reason": "operator-reviewed synthetic target",
		})
		resp := request(http.MethodPost, base, string(body))
		if resp.Code != http.StatusCreated || !strings.Contains(resp.Body.String(), `"enforced":false`) {
			t.Fatalf("approval %s: %d %s", value, resp.Code, resp.Body.String())
		}
		var output struct{ Decision struct{ ID int64 } }
		if err := json.Unmarshal(resp.Body.Bytes(), &output); err != nil || output.Decision.ID <= 0 {
			t.Fatalf("approval ID: %v %s", err, resp.Body.String())
		}
		return output.Decision.ID
	}
	hostID := approval("hostname", "target.test", false)
	peerID := approval("cidr", "127.0.0.1/32", true)
	policy, err := s.m.pg.LoadCampaignNetworkRules(context.Background(), ownerID)
	if err != nil || len(policy) != 2 || !policy[1].AllowDirect {
		t.Fatalf("operator decisions not available to evaluator: %+v %v", policy, err)
	}
	var actor string
	if err := s.m.pg.QueryRow(`SELECT actor FROM campaign_network_rules WHERE id=$1`, hostID).Scan(&actor); err != nil || !strings.HasPrefix(actor, "operator-session:") {
		t.Fatalf("operator session provenance: %q %v", actor, err)
	}
	if otherPolicy, err := s.m.pg.LoadCampaignNetworkRules(context.Background(), otherID); err != nil || len(otherPolicy) != 0 {
		t.Fatalf("cross-campaign authorization: %+v %v", otherPolicy, err)
	}
	wrong := "/api/tasks/" + other.ID + "/network-decisions/" + strconv.FormatInt(hostID, 10) + "/revoke"
	if resp := request(http.MethodPost, wrong, `{"reason":"wrong campaign"}`); resp.Code != http.StatusNotFound {
		t.Fatalf("cross-campaign revoke: %d %s", resp.Code, resp.Body.String())
	}
	revoke := base + "/" + strconv.FormatInt(peerID, 10) + "/revoke"
	if resp := request(http.MethodPost, revoke, `{"reason":"approval withdrawn"}`); resp.Code != 200 {
		t.Fatalf("revoke: %d %s", resp.Code, resp.Body.String())
	}
	policy, err = s.m.pg.LoadCampaignNetworkRules(context.Background(), ownerID)
	if err != nil || len(policy) != 1 || policy[0].TargetValue != "target.test" {
		t.Fatalf("revoked approval remained active: %+v %v", policy, err)
	}
}
