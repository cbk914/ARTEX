package server

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) networkDecisionTask(w http.ResponseWriter, r *http.Request) (int64, string, bool) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return 0, "", false
	}
	canonical := strconv.FormatInt(id, 10)
	if _, ok := s.m.Task(canonical); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return 0, "", false
	}
	return id, canonical, true
}

func (s *Server) networkDecisionActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, ok := parseSessionClaims(extractToken(r), s.jwtKey)
	if !ok || len(claims.ID) != 32 {
		writeErr(w, http.StatusForbidden, "operator session identifier required")
		return "", false
	}
	if _, err := hex.DecodeString(claims.ID); err != nil {
		writeErr(w, http.StatusForbidden, "operator session identifier required")
		return "", false
	}
	return "operator-session:" + claims.ID, true
}

func (s *Server) taskNetworkDecisions(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.networkDecisionTask(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rules, err := pg.ActiveCampaignNetworkRules(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "network decisions unavailable")
		return
	}
	if rules == nil {
		rules = []db.CampaignNetworkRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": rules, "enforced": false})
}

func (s *Server) addTaskNetworkDecision(w http.ResponseWriter, r *http.Request) {
	id, taskKey, ok := s.networkDecisionTask(w, r)
	if !ok {
		return
	}
	actor, ok := s.networkDecisionActor(w, r)
	if !ok {
		return
	}
	if !s.engine.beginTaskOperation(taskKey) {
		writeErr(w, http.StatusConflict, "task is being deleted")
		return
	}
	defer s.engine.decInflight(taskKey)
	var body struct {
		Effect      string    `json:"effect"`
		TargetKind  string    `json:"target_kind"`
		TargetValue string    `json:"target_value"`
		Protocol    string    `json:"protocol"`
		PortStart   int       `json:"port_start"`
		PortEnd     int       `json:"port_end"`
		AllowDirect bool      `json:"allow_direct"`
		ExpiresAt   time.Time `json:"expires_at"`
		Reason      string    `json:"reason"`
	}
	if !strictOperatorJSON(w, r, &body) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rule, err := pg.RecordCampaignNetworkRule(r.Context(), id, actor, db.CampaignNetworkRuleInput{
		Effect: body.Effect, TargetKind: body.TargetKind, TargetValue: body.TargetValue,
		Protocol: body.Protocol, PortStart: body.PortStart, PortEnd: body.PortEnd,
		AllowDirect: body.AllowDirect, ExpiresAt: body.ExpiresAt, Reason: body.Reason,
	})
	if errors.Is(err, db.ErrNetworkRuleUnavailable) {
		writeErr(w, http.StatusNotFound, "task not found")
	} else if err != nil {
		if errors.Is(err, db.ErrInvalidNetworkRule) {
			writeErr(w, http.StatusBadRequest, "invalid network decision")
		} else {
			writeErr(w, http.StatusServiceUnavailable, "network decisions unavailable")
		}
	} else {
		writeJSON(w, http.StatusCreated, map[string]any{"decision": rule, "enforced": false})
	}
}

func (s *Server) revokeTaskNetworkDecision(w http.ResponseWriter, r *http.Request) {
	id, taskKey, ok := s.networkDecisionTask(w, r)
	if !ok {
		return
	}
	actor, ok := s.networkDecisionActor(w, r)
	if !ok {
		return
	}
	ruleID, ok := pathInt(r, "rule_id")
	if !ok || ruleID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid network decision id")
		return
	}
	if !s.engine.beginTaskOperation(taskKey) {
		writeErr(w, http.StatusConflict, "task is being deleted")
		return
	}
	defer s.engine.decInflight(taskKey)
	var body struct {
		Reason string `json:"reason"`
	}
	if !strictOperatorJSON(w, r, &body) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	err := pg.RevokeCampaignNetworkRule(r.Context(), id, ruleID, actor, body.Reason)
	if errors.Is(err, db.ErrNetworkRuleUnavailable) {
		writeErr(w, http.StatusNotFound, "network decision not found")
	} else if errors.Is(err, db.ErrInvalidNetworkRule) {
		writeErr(w, http.StatusBadRequest, "invalid network decision revocation")
	} else if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "network decisions unavailable")
	} else {
		writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "enforced": false})
	}
}
