//go:build linux && isolation_probe

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

// Opt-in diagnostic only: confirms the present shared-identity boundary with
// disposable synthetic files and processes. The future broker acceptance test
// must invert these expectations and assert denial.
func TestSharedExecutorCrossCampaignExposureProbe(t *testing.T) {
	f := newExecRootFixture(t)
	other := agent.EnsureRunDir(f.data, 2, 0)
	private := filepath.Join(other, "private.txt")
	if err := os.WriteFile(private, []byte("CAMPAIGN_B_SENTINEL"), 0o660); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", `cat "$OTHER"; printf CAMPAIGN_A_REPLACED > "$OTHER"; printf A_CACHE > "$HOME/campaign-marker"`)
	cmd.Dir = f.work
	cmd.Env = append(os.Environ(), "OTHER="+private)
	applyExecCredential(cmd, f.priv)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("campaign A probe: %v: %s", err, out)
	}
	if string(out) != "CAMPAIGN_B_SENTINEL" {
		t.Fatalf("unexpected A read: %q", out)
	}
	if body, err := os.ReadFile(private); err != nil || string(body) != "CAMPAIGN_A_REPLACED" {
		t.Fatalf("A could not replace B file: %q %v", body, err)
	}
	second := exec.Command("sh", "-c", `cat "$HOME/campaign-marker"`)
	second.Dir = other
	applyExecCredential(second, f.priv)
	cache, err := second.CombinedOutput()
	if err != nil || strings.TrimSpace(string(cache)) != "A_CACHE" {
		t.Fatalf("B could not read A HOME state: %q %v", cache, err)
	}
	victim := exec.Command("sleep", "30")
	victim.Dir = other
	applyExecCredential(victim, f.priv)
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { victim.Process.Kill(); victim.Wait() }()
	attacker := exec.Command("sh", "-c", `kill -TERM "$VICTIM"`)
	attacker.Dir = f.work
	attacker.Env = append(os.Environ(), "VICTIM="+strconv.Itoa(victim.Process.Pid))
	applyExecCredential(attacker, f.priv)
	if out, err := attacker.CombinedOutput(); err != nil {
		t.Fatalf("A could not signal B process: %v %q", err, out)
	}
	t.Log("observed: A read/wrote B private file; B read A HOME marker; A signaled B process")
}
