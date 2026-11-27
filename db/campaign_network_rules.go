package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/networkpolicy"
)

var ErrNetworkRuleUnavailable = errors.New("campaign network rule is unavailable")
var ErrInvalidNetworkRule = errors.New("invalid campaign network rule")

// CampaignNetworkRule is an operator decision staged for a future broker-owned
// egress gateway. No current ARTEX execution path consumes these rows.
type CampaignNetworkRule struct {
	ID          int64
	TaskID      int64
	Effect      string // allow or deny
	TargetKind  string // hostname, ip, or cidr
	TargetValue string
	Protocol    string // tcp or udp
	PortStart   int
	PortEnd     int
	AllowDirect bool
	Actor       string
	Reason      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

type CampaignNetworkRuleInput struct {
	Effect      string
	TargetKind  string
	TargetValue string
	Protocol    string
	PortStart   int
	PortEnd     int
	AllowDirect bool
	ExpiresAt   time.Time
	Reason      string
}

func validateNetworkActorAndReason(actor, reason string) error {
	if strings.TrimSpace(actor) != actor || len(actor) < 1 || len(actor) > 128 ||
		strings.TrimSpace(reason) != reason || len(reason) < 1 || len(reason) > 1000 {
		return errors.New("network decision requires a bounded actor and reason")
	}
	return nil
}

func normalizeNetworkTarget(kind, raw string) (string, error) {
	return networkpolicy.NormalizeTarget(kind, raw)
}

// RecordCampaignNetworkRule writes a distinct operator decision. It is not
// called by agent or scanner paths and does not itself enable network egress.
// An authenticated operator API must supply actor when the gateway is ready.
func (d *DB) RecordCampaignNetworkRule(ctx context.Context, taskID int64, actor string, input CampaignNetworkRuleInput) (CampaignNetworkRule, error) {
	var rule CampaignNetworkRule
	if taskID <= 0 || validateNetworkActorAndReason(actor, input.Reason) != nil {
		return rule, fmt.Errorf("%w: provenance", ErrInvalidNetworkRule)
	}
	if input.Effect != "allow" && input.Effect != "deny" {
		return rule, fmt.Errorf("%w: effect", ErrInvalidNetworkRule)
	}
	if input.Protocol != "tcp" && input.Protocol != "udp" {
		return rule, fmt.Errorf("%w: protocol", ErrInvalidNetworkRule)
	}
	if input.PortStart < 1 || input.PortEnd > 65535 || input.PortEnd < input.PortStart {
		return rule, fmt.Errorf("%w: ports", ErrInvalidNetworkRule)
	}
	if input.AllowDirect && input.TargetKind == "hostname" {
		return rule, fmt.Errorf("%w: hostname cannot approve direct IP access", ErrInvalidNetworkRule)
	}
	if !input.ExpiresAt.After(time.Now()) {
		return rule, fmt.Errorf("%w: expiry", ErrInvalidNetworkRule)
	}
	target, err := normalizeNetworkTarget(input.TargetKind, input.TargetValue)
	if err != nil {
		return rule, fmt.Errorf("%w: %v", ErrInvalidNetworkRule, err)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return rule, err
	}
	defer tx.Rollback()
	var activeTaskID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&activeTaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rule, ErrNetworkRuleUnavailable
		}
		return rule, err
	}
	rule = CampaignNetworkRule{TaskID: taskID, Effect: input.Effect, TargetKind: input.TargetKind,
		TargetValue: target, Protocol: input.Protocol, PortStart: input.PortStart, PortEnd: input.PortEnd,
		AllowDirect: input.AllowDirect,
		Actor:       actor, Reason: input.Reason, ExpiresAt: input.ExpiresAt.UTC()}
	err = tx.QueryRowContext(ctx, `INSERT INTO campaign_network_rules
(task_id,effect,target_kind,target_value,protocol,port_start,port_end,allow_direct,actor,reason,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,created_at`,
		rule.TaskID, rule.Effect, rule.TargetKind, rule.TargetValue, rule.Protocol,
		rule.PortStart, rule.PortEnd, rule.AllowDirect, rule.Actor, rule.Reason, rule.ExpiresAt).Scan(&rule.ID, &rule.CreatedAt)
	if err != nil {
		return CampaignNetworkRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return CampaignNetworkRule{}, err
	}
	return rule, nil
}

// ActiveCampaignNetworkRules reads current, non-revoked decisions. A gateway
// must call this for every new connection and fail closed on any returned error.
func (d *DB) ActiveCampaignNetworkRules(ctx context.Context, taskID int64) ([]CampaignNetworkRule, error) {
	if taskID <= 0 {
		return nil, ErrNetworkRuleUnavailable
	}
	rows, err := d.QueryContext(ctx, `SELECT r.id,r.task_id,r.effect,r.target_kind,r.target_value,r.protocol,
r.port_start,r.port_end,r.allow_direct,r.actor,r.reason,r.created_at,r.expires_at
FROM campaign_network_rules r
JOIN tasks t ON t.id=r.task_id AND t.deleted_at IS NULL
LEFT JOIN campaign_network_rule_revocations v ON v.rule_id=r.id
WHERE r.task_id=$1 AND r.expires_at>now() AND v.rule_id IS NULL
ORDER BY r.id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("read campaign network rules: %w", err)
	}
	defer rows.Close()
	var rules []CampaignNetworkRule
	for rows.Next() {
		var rule CampaignNetworkRule
		if err := rows.Scan(&rule.ID, &rule.TaskID, &rule.Effect, &rule.TargetKind,
			&rule.TargetValue, &rule.Protocol, &rule.PortStart, &rule.PortEnd, &rule.AllowDirect,
			&rule.Actor, &rule.Reason, &rule.CreatedAt, &rule.ExpiresAt); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// LoadCampaignNetworkRules adapts the current database decisions to the
// independent network gate. The gateway must bind taskID to an opaque sandbox
// handle before using this source; this method does not establish that grant.
func (d *DB) LoadCampaignNetworkRules(ctx context.Context, taskID int64) ([]networkpolicy.Rule, error) {
	stored, err := d.ActiveCampaignNetworkRules(ctx, taskID)
	if err != nil {
		return nil, err
	}
	rules := make([]networkpolicy.Rule, 0, len(stored))
	for _, row := range stored {
		rules = append(rules, networkpolicy.Rule{
			Effect: row.Effect, TargetKind: row.TargetKind, TargetValue: row.TargetValue,
			Protocol: row.Protocol, PortStart: row.PortStart, PortEnd: row.PortEnd,
			AllowDirect: row.AllowDirect, ExpiresAt: row.ExpiresAt,
		})
	}
	return rules, nil
}

// RevokeCampaignNetworkRule appends a revocation; the grant and its original
// provenance stay intact. A repeated or cross-task revoke cannot change it.
func (d *DB) RevokeCampaignNetworkRule(ctx context.Context, taskID, ruleID int64, actor, reason string) error {
	if taskID <= 0 || ruleID <= 0 || validateNetworkActorAndReason(actor, reason) != nil {
		return fmt.Errorf("%w: revocation", ErrInvalidNetworkRule)
	}
	var inserted int64
	err := d.QueryRowContext(ctx, `INSERT INTO campaign_network_rule_revocations (rule_id,actor,reason)
SELECT r.id,$3,$4 FROM campaign_network_rules r
JOIN tasks t ON t.id=r.task_id AND t.deleted_at IS NULL
WHERE r.task_id=$1 AND r.id=$2
ON CONFLICT (rule_id) DO NOTHING RETURNING rule_id`, taskID, ruleID, actor, reason).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNetworkRuleUnavailable
	}
	return err
}
