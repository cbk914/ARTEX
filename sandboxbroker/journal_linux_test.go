//go:build linux

package sandboxbroker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func journalFixture(t *testing.T) (*FileJournal, Spec) {
	t.Helper()
	path := identityFixture(t)
	identity, err := OpenBrokerIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identity.Close() })
	journal, err := identity.OpenJournal()
	if err != nil {
		t.Fatal(err)
	}
	return journal, Spec{Name: "artex-campaign-" + strings.Repeat("a", 32), Image: testImage, Token: strings.Repeat("b", 64), Owner: identity.Owner}
}

func TestFileJournalRecordAndForget(t *testing.T) {
	j, spec := journalFixture(t)
	if err := j.Record(spec); err != nil {
		t.Fatal(err)
	}
	if err := j.Record(spec); err == nil {
		t.Fatal("overwrote existing intent")
	}
	entries, err := j.Entries()
	if err != nil || len(entries) != 1 || entries[0] != spec {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	foreign := spec
	foreign.Token = strings.Repeat("c", 64)
	if err := j.Forget(foreign); err == nil {
		t.Fatal("forgot mismatched intent")
	}
	if err := j.Forget(spec); err != nil {
		t.Fatal(err)
	}
	entries, err = j.Entries()
	if err != nil || len(entries) != 0 {
		t.Fatalf("remaining entries=%v err=%v", entries, err)
	}
}

func TestFileJournalRejectsTamperedRecord(t *testing.T) {
	j, spec := journalFixture(t)
	path, _ := j.path(spec)
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Entries(); err == nil {
		t.Fatal("accepted symlinked intent")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Entries(); err == nil {
		t.Fatal("accepted malformed intent")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(j.dir, "unexpected"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Entries(); err == nil {
		t.Fatal("accepted unexpected journal entry")
	}
}

func TestRecoverRecordedMissingContainerClearsIntent(t *testing.T) {
	j, spec := journalFixture(t)
	if err := j.Record(spec); err != nil {
		t.Fatal(err)
	}
	r := &recordingRunner{responses: map[string][]byte{"ps": nil}}
	d := &DockerEngine{runner: r}
	if err := d.RecoverRecorded(context.Background(), j, testImage); err != nil {
		t.Fatal(err)
	}
	entries, err := j.Entries()
	if err != nil || len(entries) != 0 {
		t.Fatalf("stale intent remains: %v %v", entries, err)
	}
	for _, call := range r.calls {
		if call[0] == "rm" {
			t.Fatal("removed container without matching journaled candidate")
		}
	}
}

func TestRecoverRecordedRequiresFullAttestation(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned stopped", true: "foreign token"}[foreign], func(t *testing.T) {
			j, spec := journalFixture(t)
			if err := j.Record(spec); err != nil {
				t.Fatal(err)
			}
			id := strings.Repeat("d", 64)
			token := spec.Token
			if foreign {
				token = strings.Repeat("e", 64)
			}
			info := map[string]any{
				"Id": id, "Name": "/" + spec.Name, "Image": testImage,
				"State": map[string]any{"Running": false},
				"Config": map[string]any{"User": sandboxUser, "Labels": map[string]string{ownershipLabel: token, ownerLabel: spec.Owner},
					"Env": []string{"HOME=/campaign", "TMPDIR=/tmp", "XDG_CONFIG_HOME=/campaign/.config", "XDG_CACHE_HOME=/campaign/.cache", "XDG_DATA_HOME=/campaign/.local/share", "XDG_STATE_HOME=/campaign/.local/state", "XDG_RUNTIME_DIR=/campaign/.run"}},
				"HostConfig": map[string]any{"NetworkMode": "none", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "Memory": memoryLimit, "MemorySwap": memoryLimit, "PidsLimit": pidLimit, "NanoCpus": nanoCPUs,
					"Tmpfs": map[string]string{"/tmp": "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700", "/campaign": "rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=0700", "/artifacts": "rw,nosuid,nodev,noexec,size=64m,uid=0,gid=0,mode=0755", "/app/data": "rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700", "/app/keys": "rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700"}},
				"NetworkSettings": map[string]any{"Networks": map[string]any{"none": map[string]any{}}},
			}
			r := &recordingRunner{responses: map[string][]byte{"ps": []byte(id + "\n"), "image": jsonArray(t, map[string]any{"Id": testImage}), "inspect": jsonArray(t, info)}}
			d := &DockerEngine{runner: r}
			err := d.RecoverRecorded(context.Background(), j, testImage)
			if (err != nil) != foreign {
				t.Fatalf("recovery err=%v, foreign=%v", err, foreign)
			}
			removed := false
			for _, call := range r.calls {
				if call[0] == "rm" {
					removed = true
					if call[len(call)-1] != id {
						t.Fatalf("removed wrong ID: %v", call)
					}
				}
			}
			if removed == foreign {
				t.Fatalf("removed=%v foreign=%v", removed, foreign)
			}
			entries, err := j.Entries()
			if err != nil || (len(entries) == 0) == foreign {
				t.Fatalf("journal entries=%v err=%v", entries, err)
			}
		})
	}
}
