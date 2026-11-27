package db

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

func TestCampaignNetworkRulesMigrationPreservesPriorData(t *testing.T) {
	dsn := scratchDSN(t, "networkupgrade")
	prior := fstest.MapFS{}
	entries, err := fs.ReadDir(migrationsFS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == "0016_campaign_network_rules.sql" {
			continue
		}
		content, err := fs.ReadFile(migrationsFS(), entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		prior[entry.Name()] = &fstest.MapFile{Data: content}
	}
	before, err := openWithMigrations(dsn, prior)
	if err != nil {
		t.Fatal(err)
	}
	task, err := before.CreateTaskWithOptions("synthetic pre-upgrade task", "local fixture", TaskCreateOptions{})
	if err != nil {
		before.Close()
		t.Fatal(err)
	}
	if _, err := before.Exec(`INSERT INTO task_scope(task_id,kind,domain,source) VALUES ($1,'root_domain','preserved.test','agent')`, task.ID); err != nil {
		before.Close()
		t.Fatal(err)
	}
	if err := before.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	var count, version int
	if err := after.QueryRow(`SELECT count(*), max(version) FROM schema_migrations`).Scan(&count, &version); err != nil || count != 16 || version != 16 {
		t.Fatalf("migration state %d/%d: %v", count, version, err)
	}
	var preserved string
	if err := after.QueryRow(`SELECT domain FROM task_scope WHERE task_id=$1 AND source='agent'`, task.ID).Scan(&preserved); err != nil || preserved != "preserved.test" {
		t.Fatalf("coverage row changed: %q %v", preserved, err)
	}
	rules, err := after.ActiveCampaignNetworkRules(context.Background(), task.ID)
	if err != nil || len(rules) != 0 {
		t.Fatalf("migration created an implicit network grant: %+v %v", rules, err)
	}
}

func TestCampaignNetworkRulesStaySeparateFromCoverage(t *testing.T) {
	dsn := scratchDSN(t, "networkrules")
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	source, err := d.CreateTaskWithOptions("synthetic source", "local target only", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := d.CreateTaskWithOptions("synthetic child", "inherited context", TaskCreateOptions{SourceTaskIDs: []int64{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO task_scope(task_id,kind,domain,source) VALUES ($1,'root_domain','fixture.test','agent')`, source.ID); err != nil {
		t.Fatal(err)
	}
	for _, taskID := range []int64{source.ID, child.ID} {
		rules, err := d.ActiveCampaignNetworkRules(ctx, taskID)
		if err != nil || len(rules) != 0 {
			t.Fatalf("coverage or inheritance granted network access: task=%d rules=%+v err=%v", taskID, rules, err)
		}
	}
	allow, err := d.RecordCampaignNetworkRule(ctx, source.ID, "local-admin", CampaignNetworkRuleInput{
		Effect: "allow", TargetKind: "hostname", TargetValue: "EXAMPLE.test.", Protocol: "tcp",
		PortStart: 8443, PortEnd: 8443, ExpiresAt: time.Now().Add(time.Hour), Reason: "synthetic approved target",
	})
	if err != nil || allow.TargetValue != "example.test" {
		t.Fatalf("record allow: %+v %v", allow, err)
	}
	deny, err := d.RecordCampaignNetworkRule(ctx, source.ID, "local-admin", CampaignNetworkRuleInput{
		Effect: "deny", TargetKind: "ip", TargetValue: "127.0.0.1", Protocol: "tcp",
		PortStart: 8443, PortEnd: 8443, ExpiresAt: time.Now().Add(time.Hour), Reason: "synthetic excluded peer",
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	rules, err := other.ActiveCampaignNetworkRules(ctx, source.ID)
	if err != nil || len(rules) != 2 || rules[0].ID != allow.ID || rules[1].ID != deny.ID {
		t.Fatalf("cross-connection rules: %+v %v", rules, err)
	}
	if inherited, err := other.ActiveCampaignNetworkRules(ctx, child.ID); err != nil || len(inherited) != 0 {
		t.Fatalf("source grant inherited: %+v %v", inherited, err)
	}
	if err := other.RevokeCampaignNetworkRule(ctx, child.ID, allow.ID, "local-admin", "wrong task"); !errors.Is(err, ErrNetworkRuleUnavailable) {
		t.Fatalf("cross-task revoke: %v", err)
	}
	if err := other.RevokeCampaignNetworkRule(ctx, source.ID, allow.ID, "local-admin", "approval withdrawn"); err != nil {
		t.Fatal(err)
	}
	rules, err = d.ActiveCampaignNetworkRules(ctx, source.ID)
	if err != nil || len(rules) != 1 || rules[0].ID != deny.ID {
		t.Fatalf("revocation not immediately visible: %+v %v", rules, err)
	}
	if _, err := d.Exec(`INSERT INTO campaign_network_rules
(task_id,effect,target_kind,target_value,protocol,port_start,port_end,actor,reason,created_at,expires_at)
VALUES ($1,'allow','ip','127.0.0.2','tcp',8443,8443,'local-admin','expired fixture',now()-interval '2 hours',now()-interval '1 hour')`, source.ID); err != nil {
		t.Fatal(err)
	}
	rules, err = d.ActiveCampaignNetworkRules(ctx, source.ID)
	if err != nil || len(rules) != 1 || rules[0].ID != deny.ID {
		t.Fatalf("expired authorization remained effective: %+v %v", rules, err)
	}
	var actor, reason string
	if err := d.QueryRow(`SELECT actor,reason FROM campaign_network_rule_revocations WHERE rule_id=$1`, allow.ID).Scan(&actor, &reason); err != nil || actor != "local-admin" || reason != "approval withdrawn" {
		t.Fatalf("revocation provenance: %q %q %v", actor, reason, err)
	}
	if _, err := d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, source.ID); err != nil {
		t.Fatal(err)
	}
	rules, err = d.ActiveCampaignNetworkRules(ctx, source.ID)
	if err != nil || len(rules) != 0 {
		t.Fatalf("deleted task retained effective rules: %+v %v", rules, err)
	}
	var retained int
	if err := d.QueryRow(`SELECT count(*) FROM campaign_network_rules WHERE task_id=$1`, source.ID).Scan(&retained); err != nil || retained != 3 {
		t.Fatalf("audit provenance was removed: %d %v", retained, err)
	}
}

func TestCampaignNetworkRuleValidation(t *testing.T) {
	dsn := scratchDSN(t, "networkvalidation")
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTaskWithOptions("synthetic validation", "local targets only", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	valid := CampaignNetworkRuleInput{Effect: "allow", TargetKind: "ip", TargetValue: "127.0.0.1", Protocol: "tcp",
		PortStart: 443, PortEnd: 443, ExpiresAt: time.Now().Add(time.Hour), Reason: "synthetic approval"}
	for _, change := range []func(*CampaignNetworkRuleInput){
		func(in *CampaignNetworkRuleInput) { in.TargetKind, in.TargetValue = "hostname", "bad..test" },
		func(in *CampaignNetworkRuleInput) { in.TargetKind = "hostname" },
		func(in *CampaignNetworkRuleInput) { in.TargetValue = "127.0.0.1:443" },
		func(in *CampaignNetworkRuleInput) { in.TargetKind, in.TargetValue = "cidr", "bad/24" },
		func(in *CampaignNetworkRuleInput) { in.Protocol = "icmp" },
		func(in *CampaignNetworkRuleInput) { in.PortStart = 0 },
		func(in *CampaignNetworkRuleInput) { in.PortStart = 444 },
		func(in *CampaignNetworkRuleInput) { in.ExpiresAt = time.Now().Add(-time.Hour) },
		func(in *CampaignNetworkRuleInput) { in.Effect = "observe" },
		func(in *CampaignNetworkRuleInput) { in.Reason = "" },
	} {
		input := valid
		change(&input)
		if _, err := d.RecordCampaignNetworkRule(context.Background(), task.ID, "local-admin", input); err == nil {
			t.Fatalf("invalid network rule accepted: %+v", input)
		}
	}
	if _, err := d.RecordCampaignNetworkRule(context.Background(), task.ID, "", valid); err == nil {
		t.Fatal("rule without operator provenance was accepted")
	}
	if _, err := d.RecordCampaignNetworkRule(context.Background(), task.ID+99999, "local-admin", valid); !errors.Is(err, ErrNetworkRuleUnavailable) {
		t.Fatalf("rule for missing task: %v", err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM campaign_network_rules WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid rules were stored: %d %v", count, err)
	}
	if got, err := normalizeNetworkTarget("ip", "::ffff:127.0.0.1"); err != nil || got != "127.0.0.1" {
		t.Fatalf("mapped IPv4 normalization: %q %v", got, err)
	}
	if got, err := normalizeNetworkTarget("cidr", "2001:db8::1234/64"); err != nil || got != "2001:db8::/64" {
		t.Fatalf("IPv6 CIDR normalization: %q %v", got, err)
	}
}
