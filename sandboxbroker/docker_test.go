package sandboxbroker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingRunner struct {
	calls     [][]string
	responses map[string][]byte
	failure   string
}

func (r *recordingRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if args[0] == r.failure {
		return nil, errors.New("synthetic docker failure")
	}
	return r.responses[args[0]], nil
}
func jsonArray(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal([]any{value})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDockerCreateUsesFixedPolicy(t *testing.T) {
	id := strings.Repeat("a", 64)
	r := &recordingRunner{responses: map[string][]byte{"create": []byte(id + "\n")}}
	d := &DockerEngine{runner: r}
	spec := Spec{Name: "artex-campaign-" + strings.Repeat("b", 32), Image: testImage, Token: strings.Repeat("c", 64)}
	got, err := d.Create(context.Background(), spec)
	if err != nil || got != id {
		t.Fatalf("create: %q %v", got, err)
	}
	args := r.calls[0]
	for _, flag := range []string{"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=10001:10001", "--memory=256m", "--memory-swap=256m", "--cpus=0.5", "--pids-limit=64", "--label=" + ownershipLabel + "=" + spec.Token} {
		found := false
		for _, arg := range args {
			if arg == flag {
				found = true
			}
		}
		if !found {
			t.Errorf("missing fixed flag %s", flag)
		}
	}
	for _, forbidden := range []string{"--privileged", "--volume", "--mount", "--publish"} {
		for _, arg := range args {
			if arg == forbidden || strings.HasPrefix(arg, forbidden+"=") {
				t.Errorf("forbidden flag %s", arg)
			}
		}
	}
	if args[len(args)-3] != testImage || args[len(args)-2] != "-c" || args[len(args)-1] != "sleep infinity" {
		t.Fatal("unexpected image or command")
	}
}

func TestDockerRejectsUnexpectedImageVolume(t *testing.T) {
	r := &recordingRunner{responses: map[string][]byte{"image": jsonArray(t, map[string]any{
		"Id": testImage, "Config": map[string]any{"Volumes": map[string]any{"/secrets": map[string]any{}}},
	})}}
	d := &DockerEngine{runner: r}
	if err := d.CheckImage(context.Background(), testImage); err == nil {
		t.Fatal("accepted unapproved image volume")
	}
}

func TestDockerCreateNameConflictDoesNotRemoveForeignContainer(t *testing.T) {
	id := strings.Repeat("e", 64)
	spec := Spec{Name: "artex-campaign-" + strings.Repeat("b", 32), Image: testImage, Token: strings.Repeat("c", 64)}
	for _, tc := range []struct {
		name, label string
		wantRemove  bool
	}{
		{"foreign", strings.Repeat("d", 64), false},
		{"owned", spec.Token, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recordingRunner{failure: "create", responses: map[string][]byte{"inspect": jsonArray(t, map[string]any{
				"Id": id, "Name": "/" + spec.Name, "Config": map[string]any{"Labels": map[string]string{ownershipLabel: tc.label}},
			})}}
			d := &DockerEngine{runner: r}
			if _, err := d.Create(context.Background(), spec); err == nil {
				t.Fatal("expected create failure")
			}
			removed := false
			for _, call := range r.calls {
				if call[0] == "rm" {
					removed = true
					if call[len(call)-1] != id {
						t.Fatalf("removed by unverified name: %v", call)
					}
				}
			}
			if removed != tc.wantRemove {
				t.Fatalf("removed=%v want %v, calls=%v", removed, tc.wantRemove, r.calls)
			}
		})
	}
}

func TestDockerRejectsUnapprovedMountAndNetwork(t *testing.T) {
	id := strings.Repeat("b", 64)
	spec := Spec{Name: "artex-campaign-" + strings.Repeat("c", 32), Image: testImage, Token: strings.Repeat("d", 64)}
	base := map[string]any{
		"Id": id, "Name": "/" + spec.Name, "Image": testImage,
		"State": map[string]any{"Running": true}, "Config": map[string]any{"User": sandboxUser, "Labels": map[string]string{ownershipLabel: spec.Token}},
		"HostConfig": map[string]any{"NetworkMode": "none", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "Memory": memoryLimit, "MemorySwap": memoryLimit, "PidsLimit": pidLimit, "NanoCpus": nanoCPUs,
			"Tmpfs": map[string]string{"/tmp": "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700", "/campaign": "rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=0700", "/app/data": "rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700", "/app/keys": "rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700"}},
		"Mounts":          []map[string]string{},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"none": map[string]any{}}},
	}
	r := &recordingRunner{responses: map[string][]byte{"image": jsonArray(t, map[string]any{"Id": testImage}), "inspect": jsonArray(t, base)}}
	d := &DockerEngine{runner: r}
	if err := d.Verify(context.Background(), id, spec); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	base["Mounts"] = append(base["Mounts"].([]map[string]string), map[string]string{"Type": "bind", "Destination": "/host"})
	r.responses["inspect"] = jsonArray(t, base)
	if err := d.Verify(context.Background(), id, spec); err == nil {
		t.Fatal("accepted host bind")
	}
	base["Mounts"] = []map[string]string{}
	base["NetworkSettings"] = map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}
	r.responses["inspect"] = jsonArray(t, base)
	if err := d.Verify(context.Background(), id, spec); err == nil {
		t.Fatal("accepted bridge network")
	}
}

func TestDockerExecKeepsCommandAfterContainerID(t *testing.T) {
	id := strings.Repeat("e", 64)
	r := &recordingRunner{responses: map[string][]byte{"exec": []byte("ok")}}
	d := &DockerEngine{runner: r}
	command := "--privileged; echo hello"
	out, err := d.Exec(context.Background(), id, command)
	if err != nil || out != "ok" {
		t.Fatalf("exec=%q %v", out, err)
	}
	if !reflect.DeepEqual(r.calls[0], []string{"exec", id, "/bin/sh", "-c", command}) {
		t.Fatalf("unexpected Docker arguments: %v", r.calls[0])
	}
}

func TestDockerOutputIsBoundedBeforeAllocation(t *testing.T) {
	output := &boundedOutput{}
	if n, err := output.Write(make([]byte, maxDockerOutput)); err != nil || n != maxDockerOutput {
		t.Fatalf("within limit: %d %v", n, err)
	}
	if n, err := output.Write([]byte("more")); !errors.Is(err, errDockerOutputLimit) || n != 0 {
		t.Fatalf("over limit: %d %v", n, err)
	}
	data, exceeded := output.result()
	if !exceeded || len(data) != maxDockerOutput {
		t.Fatalf("output grew past cap: %d, exceeded=%v", len(data), exceeded)
	}
}
