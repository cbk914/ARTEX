package sandboxbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type recordingRunner struct {
	calls     [][]string
	responses map[string][]byte
	failure   string
	input     []byte
}

func (r *recordingRunner) RunInput(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	r.input = data
	return r.Run(ctx, args...)
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
	spec := Spec{Name: "artex-campaign-" + strings.Repeat("b", 32), Image: testImage, Token: strings.Repeat("c", 64), Owner: strings.Repeat("f", 32)}
	got, err := d.Create(context.Background(), spec)
	if err != nil || got != id {
		t.Fatalf("create: %q %v", got, err)
	}
	args := r.calls[0]
	for _, flag := range []string{"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=10001:10001", "--memory=256m", "--memory-swap=256m", "--cpus=0.5", "--pids-limit=64", "--tmpfs=/artifacts:rw,nosuid,nodev,noexec,size=64m,uid=0,gid=0,mode=0755", "--label=" + ownershipLabel + "=" + spec.Token, "--label=" + ownerLabel + "=" + spec.Owner} {
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
	for _, entry := range []string{"HOME=/campaign", "TMPDIR=/tmp", "XDG_CONFIG_HOME=/campaign/.config", "XDG_CACHE_HOME=/campaign/.cache", "XDG_DATA_HOME=/campaign/.local/share", "XDG_STATE_HOME=/campaign/.local/state", "XDG_RUNTIME_DIR=/campaign/.run"} {
		if !contains(args, "--env="+entry) {
			t.Errorf("missing private environment %s", entry)
		}
	}
	if args[len(args)-3] != testImage || args[len(args)-2] != "-c" || !strings.Contains(args[len(args)-1], "exec sleep infinity") {
		t.Fatal("unexpected image or command")
	}
}

func TestDockerArtifactStagesUnderPrivateDirectory(t *testing.T) {
	r := &recordingRunner{responses: map[string][]byte{}}
	d := &DockerEngine{runner: r}
	id := strings.Repeat("a", 64)
	if err := d.PutArtifact(context.Background(), id, "fixture.txt", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || len(r.calls[0]) != 11 || r.calls[0][0] != "exec" || r.calls[0][1] != "-i" || r.calls[0][2] != "--user=0:0" || r.calls[0][3] != id {
		t.Fatalf("unexpected Docker transfer: %v", r.calls)
	}
	if string(r.input) != "synthetic" || !strings.HasPrefix(r.calls[0][8], "/artifacts/.incoming/") || r.calls[0][9] != "/artifacts/fixture.txt" {
		t.Fatalf("unsafe artifact destination: %v", r.calls[0])
	}
	digest := sha256.Sum256(r.input)
	if r.calls[0][10] != hex.EncodeToString(digest[:]) || !strings.Contains(r.calls[0][6], "sha256sum -c -") || strings.Index(r.calls[0][6], "sha256sum -c -") > strings.Index(r.calls[0][6], "mv ") {
		t.Fatalf("artifact publication does not verify staged bytes: %v", r.calls[0])
	}
}

func TestDockerExecInputUsesSandboxUserAndBoundedStdin(t *testing.T) {
	r := &recordingRunner{responses: map[string][]byte{"exec": []byte("stdin")}}
	d := &DockerEngine{runner: r}
	id := strings.Repeat("a", 64)
	input := []byte{'a', 0, 'b'}
	output, err := d.ExecInput(context.Background(), id, "cat", input)
	if err != nil || output != "stdin" || !reflect.DeepEqual(r.input, input) {
		t.Fatalf("exec stdin: %q %v input=%v", output, err, r.input)
	}
	if len(r.calls) != 1 || !reflect.DeepEqual(r.calls[0], []string{"exec", "-i", "--workdir=/campaign", id, "/bin/sh", "-c", "cat"}) {
		t.Fatalf("unexpected Docker command: %v", r.calls)
	}
	if _, err := d.ExecInput(context.Background(), id, "cat", make([]byte, maxBrokerStdinBytes+1)); err == nil || len(r.calls) != 1 {
		t.Fatal("oversized stdin reached Docker")
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
	spec := Spec{Name: "artex-campaign-" + strings.Repeat("b", 32), Image: testImage, Token: strings.Repeat("c", 64), Owner: strings.Repeat("f", 32)}
	for _, tc := range []struct {
		name, label, owner string
		wantRemove         bool
	}{
		{"foreign token", strings.Repeat("d", 64), spec.Owner, false},
		{"foreign owner", spec.Token, strings.Repeat("e", 32), false},
		{"owned", spec.Token, spec.Owner, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recordingRunner{failure: "create", responses: map[string][]byte{"inspect": jsonArray(t, map[string]any{
				"Id": id, "Name": "/" + spec.Name, "Config": map[string]any{"Labels": map[string]string{ownershipLabel: tc.label, ownerLabel: tc.owner}},
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
	spec := Spec{Name: "artex-campaign-" + strings.Repeat("c", 32), Image: testImage, Token: strings.Repeat("d", 64), Owner: strings.Repeat("f", 32)}
	base := map[string]any{
		"Id": id, "Name": "/" + spec.Name, "Image": testImage,
		"State": map[string]any{"Running": true}, "Config": map[string]any{"User": sandboxUser, "Labels": map[string]string{ownershipLabel: spec.Token, ownerLabel: spec.Owner}, "Env": []string{"HOME=/campaign", "TMPDIR=/tmp", "XDG_CONFIG_HOME=/campaign/.config", "XDG_CACHE_HOME=/campaign/.cache", "XDG_DATA_HOME=/campaign/.local/share", "XDG_STATE_HOME=/campaign/.local/state", "XDG_RUNTIME_DIR=/campaign/.run"}},
		"HostConfig": map[string]any{"NetworkMode": "none", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "Memory": memoryLimit, "MemorySwap": memoryLimit, "PidsLimit": pidLimit, "NanoCpus": nanoCPUs,
			"Tmpfs": map[string]string{"/tmp": "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700", "/campaign": "rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=0700", "/artifacts": "rw,nosuid,nodev,noexec,size=64m,uid=0,gid=0,mode=0755", "/app/data": "rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700", "/app/keys": "rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700"}},
		"Mounts":          []map[string]string{},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"none": map[string]any{}}},
	}
	r := &recordingRunner{responses: map[string][]byte{"image": jsonArray(t, map[string]any{"Id": testImage}), "inspect": jsonArray(t, base)}}
	d := &DockerEngine{runner: r}
	if err := d.Verify(context.Background(), id, spec); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	tmpfs := base["HostConfig"].(map[string]any)["Tmpfs"].(map[string]string)
	tmpfs["/artifacts"] = "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0755"
	r.responses["inspect"] = jsonArray(t, base)
	if err := d.Verify(context.Background(), id, spec); err == nil {
		t.Fatal("accepted executor-owned artifacts directory")
	}
	tmpfs["/artifacts"] = "rw,nosuid,nodev,noexec,size=64m,uid=0,gid=0,mode=0755"
	labels := base["Config"].(map[string]any)["Labels"].(map[string]string)
	labels[ownerLabel] = strings.Repeat("e", 32)
	r.responses["inspect"] = jsonArray(t, base)
	if err := d.Verify(context.Background(), id, spec); err == nil {
		t.Fatal("accepted foreign broker owner")
	}
	labels[ownerLabel] = spec.Owner
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
	base["NetworkSettings"] = map[string]any{"Networks": map[string]any{"none": map[string]any{}}}
	config := base["Config"].(map[string]any)
	config["Env"] = []string{"HOME=/campaign", "TMPDIR=/tmp", "XDG_CONFIG_HOME=/campaign/.config", "XDG_CACHE_HOME=/shared/.cache", "XDG_DATA_HOME=/campaign/.local/share", "XDG_STATE_HOME=/campaign/.local/state", "XDG_RUNTIME_DIR=/campaign/.run"}
	r.responses["inspect"] = jsonArray(t, base)
	if err := d.Verify(context.Background(), id, spec); err == nil {
		t.Fatal("accepted shared XDG cache")
	}
	config["Env"] = []string{"HOME=/campaign", "TMPDIR=/tmp", "XDG_CONFIG_HOME=/campaign/.config", "XDG_CACHE_HOME=/campaign/.cache", "XDG_DATA_HOME=/campaign/.local/share", "XDG_STATE_HOME=/campaign/.local/state", "XDG_RUNTIME_DIR=/campaign/.run"}
	host := base["HostConfig"].(map[string]any)
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"PidMode", "host"},
		{"IpcMode", "host"},
		{"UTSMode", "host"},
		{"CgroupnsMode", "host"},
		{"UsernsMode", "host"},
		{"Devices", []map[string]string{{"PathOnHost": "/dev/kvm"}}},
		{"DeviceRequests", []map[string]string{{"Driver": "nvidia"}}},
		{"GroupAdd", []string{"docker"}},
		{"ExtraHosts", []string{"host.docker.internal:host-gateway"}},
		{"Links", []string{"other:other"}},
		{"VolumesFrom", []string{"other"}},
		{"PortBindings", map[string]any{"8080/tcp": []any{}}},
		{"SecurityOpt", []string{"no-new-privileges:true", "seccomp=unconfined"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous, present := host[tc.name]
			host[tc.name] = tc.value
			r.responses["inspect"] = jsonArray(t, base)
			if err := d.Verify(context.Background(), id, spec); err == nil {
				t.Errorf("accepted unsafe %s", tc.name)
			}
			if present {
				host[tc.name] = previous
			} else {
				delete(host, tc.name)
			}
		})
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
	if !reflect.DeepEqual(r.calls[0], []string{"exec", "--workdir=/campaign", id, "/bin/sh", "-c", command}) {
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
