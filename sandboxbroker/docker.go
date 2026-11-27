package sandboxbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	sandboxUser = "10001:10001"
	memoryLimit = int64(256 << 20)
	pidLimit    = int64(64)
	nanoCPUs    = int64(500_000_000)
)

var containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var containerName = regexp.MustCompile(`^artex-campaign-[a-f0-9]{32}$`)
var ownershipToken = regexp.MustCompile(`^[a-f0-9]{64}$`)
var brokerOwner = regexp.MustCompile(`^[a-f0-9]{32}$`)

const ownershipLabel = "org.artex.sandbox.token"
const ownerLabel = "org.artex.sandbox.owner"

type commandRunner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type cliRunner struct{ path string }

const maxDockerOutput = 1 << 20

var errDockerOutputLimit = errors.New("docker command output exceeds 1 MiB")

type boundedOutput struct {
	mu       sync.Mutex
	data     []byte
	exceeded bool
	kill     func()
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > maxDockerOutput-len(b.data) {
		b.exceeded = true
		if b.kill != nil {
			b.kill()
		}
		return 0, errDockerOutputLimit
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedOutput) result() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), b.exceeded
}

func (r cliRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.path, args...)
	output := &boundedOutput{kill: func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	data, exceeded := output.result()
	if exceeded {
		return data, errDockerOutputLimit
	}
	if err != nil {
		message := data
		if len(message) > 4096 {
			message = message[:4096]
		}
		return data, fmt.Errorf("docker command failed: %w: %s", err, strings.TrimSpace(string(message)))
	}
	return data, nil
}

// DockerEngine controls disposable containers from a trusted host process.
// Never instantiate it inside an ARTEX server or agent container.
type DockerEngine struct{ runner commandRunner }

func NewDockerEngine(dockerPath string) (*DockerEngine, error) {
	if !filepath.IsAbs(dockerPath) {
		return nil, errors.New("docker executable path must be absolute")
	}
	return &DockerEngine{runner: cliRunner{path: dockerPath}}, nil
}

type imageInfo struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
	Config      struct {
		Volumes map[string]json.RawMessage `json:"Volumes"`
	} `json:"Config"`
}

func decodeOne[T any](data []byte) (T, error) {
	var result []T
	if err := json.Unmarshal(data, &result); err != nil {
		var zero T
		return zero, err
	}
	if len(result) != 1 {
		var zero T
		return zero, errors.New("docker inspect returned unexpected count")
	}
	return result[0], nil
}

func (d *DockerEngine) CheckImage(ctx context.Context, image string) error {
	if !pinnedImage.MatchString(image) {
		return errors.New("image is not pinned")
	}
	output, err := d.runner.Run(ctx, "image", "inspect", image)
	if err != nil {
		return err
	}
	info, err := decodeOne[imageInfo](output)
	if err != nil {
		return err
	}
	matched := info.ID == image
	for _, digest := range info.RepoDigests {
		matched = matched || digest == image
	}
	if !matched {
		return errors.New("inspected image does not match pinned digest")
	}
	for path := range info.Config.Volumes {
		if path != "/app/data" && path != "/app/keys" {
			return fmt.Errorf("unapproved image volume %q", path)
		}
	}
	return nil
}

func (d *DockerEngine) Create(ctx context.Context, spec Spec) (string, error) {
	if !containerName.MatchString(spec.Name) || !pinnedImage.MatchString(spec.Image) || !ownershipToken.MatchString(spec.Token) || !brokerOwner.MatchString(spec.Owner) {
		return "", errors.New("invalid sandbox spec")
	}
	args := []string{
		"create", "--pull=never", "--name", spec.Name, "--label=" + ownershipLabel + "=" + spec.Token, "--label=" + ownerLabel + "=" + spec.Owner,
		"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--user=" + sandboxUser, "--memory=256m", "--memory-swap=256m", "--cpus=0.5", "--pids-limit=64",
		"--ulimit=nofile=1024:1024",
		"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700",
		"--tmpfs=/campaign:rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=0700",
		"--tmpfs=/artifacts:rw,nosuid,nodev,noexec,size=64m,uid=0,gid=0,mode=0755",
		"--tmpfs=/app/data:rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700",
		"--tmpfs=/app/keys:rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700",
		"--env=HOME=/campaign", "--env=TMPDIR=/tmp", "--env=XDG_CONFIG_HOME=/campaign/.config",
		"--env=XDG_CACHE_HOME=/campaign/.cache", "--env=XDG_DATA_HOME=/campaign/.local/share",
		"--env=XDG_STATE_HOME=/campaign/.local/state", "--env=XDG_RUNTIME_DIR=/campaign/.run",
		"--entrypoint=/bin/sh", spec.Image, "-c", "mkdir -p /campaign/.config /campaign/.cache /campaign/.local/share /campaign/.local/state /campaign/.run && chmod 0700 /campaign/.run && exec sleep infinity",
	}
	output, err := d.runner.Run(ctx, args...)
	if err != nil {
		return "", errors.Join(err, d.cleanupOwned(spec))
	}
	id := strings.TrimSpace(string(output))
	if !containerID.MatchString(id) {
		return "", errors.Join(errors.New("docker returned invalid container ID"), d.cleanupOwned(spec))
	}
	return id, nil
}

// cleanupOwned checks an independent random label before removing a container by
// ID. A name collision must never delete a container that the broker did not create.
func (d *DockerEngine) cleanupOwned(spec Spec) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := d.runner.Run(ctx, "inspect", spec.Name)
	if err != nil {
		return nil
	} // No confirmed owned container to remove.
	info, err := decodeOne[containerInfo](output)
	if err != nil {
		return fmt.Errorf("inspect failed creation %s: %w", spec.Name, err)
	}
	if info.Name != "/"+spec.Name || !containerID.MatchString(info.ID) || info.Config.Labels[ownershipLabel] != spec.Token || info.Config.Labels[ownerLabel] != spec.Owner {
		return nil // A colliding or replaced name is not ours.
	}
	_, err = d.runner.Run(ctx, "rm", "-f", "-v", info.ID)
	if err != nil {
		return fmt.Errorf("remove failed creation %s: %w", spec.Name, err)
	}
	return nil
}

func (d *DockerEngine) Start(ctx context.Context, id string) error {
	if !containerID.MatchString(id) {
		return errors.New("invalid container ID")
	}
	_, err := d.runner.Run(ctx, "start", id)
	return err
}

func (d *DockerEngine) Exec(ctx context.Context, id, command string) (string, error) {
	if !containerID.MatchString(id) || command == "" || len(command) > 64<<10 || strings.IndexByte(command, 0) >= 0 {
		return "", errors.New("invalid sandbox execution request")
	}
	output, err := d.runner.Run(ctx, "exec", id, "/bin/sh", "-c", command)
	return string(output), err
}

type containerInfo struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		User   string            `json:"User"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode    string                     `json:"NetworkMode"`
		PidMode        string                     `json:"PidMode"`
		IpcMode        string                     `json:"IpcMode"`
		UTSMode        string                     `json:"UTSMode"`
		CgroupnsMode   string                     `json:"CgroupnsMode"`
		UsernsMode     string                     `json:"UsernsMode"`
		ReadonlyRootfs bool                       `json:"ReadonlyRootfs"`
		CapAdd         []string                   `json:"CapAdd"`
		CapDrop        []string                   `json:"CapDrop"`
		SecurityOpt    []string                   `json:"SecurityOpt"`
		Devices        []json.RawMessage          `json:"Devices"`
		DeviceRequests []json.RawMessage          `json:"DeviceRequests"`
		GroupAdd       []string                   `json:"GroupAdd"`
		ExtraHosts     []string                   `json:"ExtraHosts"`
		Links          []string                   `json:"Links"`
		VolumesFrom    []string                   `json:"VolumesFrom"`
		PortBindings   map[string]json.RawMessage `json:"PortBindings"`
		Memory         int64                      `json:"Memory"`
		MemorySwap     int64                      `json:"MemorySwap"`
		PidsLimit      int64                      `json:"PidsLimit"`
		NanoCpus       int64                      `json:"NanoCpus"`
		Binds          []string                   `json:"Binds"`
		Tmpfs          map[string]string          `json:"Tmpfs"`
		Privileged     bool                       `json:"Privileged"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func privateNamespaceMode(mode string) bool { return mode == "" || mode == "private" }

func (d *DockerEngine) Verify(ctx context.Context, id string, spec Spec) error {
	return d.verify(ctx, id, spec, true)
}

func (d *DockerEngine) verify(ctx context.Context, id string, spec Spec, requireRunning bool) error {
	if !containerID.MatchString(id) {
		return errors.New("invalid container ID")
	}
	if err := d.CheckImage(ctx, spec.Image); err != nil {
		return err
	}
	imageOutput, err := d.runner.Run(ctx, "image", "inspect", spec.Image)
	if err != nil {
		return err
	}
	image, err := decodeOne[imageInfo](imageOutput)
	if err != nil {
		return err
	}
	output, err := d.runner.Run(ctx, "inspect", id)
	if err != nil {
		return err
	}
	info, err := decodeOne[containerInfo](output)
	if err != nil {
		return err
	}
	h := info.HostConfig
	if info.ID != id || info.Name != "/"+spec.Name || info.Config.Labels[ownershipLabel] != spec.Token || info.Config.Labels[ownerLabel] != spec.Owner || info.Image != image.ID || (requireRunning && !info.State.Running) || info.Config.User != sandboxUser ||
		h.NetworkMode != "none" || !privateNamespaceMode(h.PidMode) || !privateNamespaceMode(h.IpcMode) ||
		!privateNamespaceMode(h.UTSMode) || !privateNamespaceMode(h.CgroupnsMode) || !privateNamespaceMode(h.UsernsMode) ||
		!h.ReadonlyRootfs || h.Privileged || len(h.CapAdd) != 0 || !contains(h.CapDrop, "ALL") ||
		len(h.SecurityOpt) != 1 || h.SecurityOpt[0] != "no-new-privileges:true" ||
		len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.GroupAdd) != 0 ||
		len(h.ExtraHosts) != 0 || len(h.Links) != 0 || len(h.VolumesFrom) != 0 || len(h.PortBindings) != 0 ||
		h.Memory != memoryLimit || h.MemorySwap != memoryLimit ||
		h.PidsLimit != pidLimit || h.NanoCpus != nanoCPUs || len(h.Binds) != 0 || len(info.NetworkSettings.Networks) != 1 {
		return errors.New("sandbox container violates fixed isolation policy")
	}
	if _, onlyNone := info.NetworkSettings.Networks["none"]; !onlyNone {
		return errors.New("sandbox joined an unapproved network")
	}
	env := make(map[string]string, len(info.Config.Env))
	for _, entry := range info.Config.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return errors.New("sandbox has malformed environment")
		}
		if _, duplicate := env[key]; duplicate {
			return fmt.Errorf("sandbox has duplicate environment key %q", key)
		}
		env[key] = value
	}
	for key, want := range map[string]string{
		"HOME": "/campaign", "TMPDIR": "/tmp", "XDG_CONFIG_HOME": "/campaign/.config",
		"XDG_CACHE_HOME": "/campaign/.cache", "XDG_DATA_HOME": "/campaign/.local/share",
		"XDG_STATE_HOME": "/campaign/.local/state", "XDG_RUNTIME_DIR": "/campaign/.run",
	} {
		if env[key] != want {
			return fmt.Errorf("sandbox environment %s violates private path policy", key)
		}
	}
	if len(h.Tmpfs) != 5 {
		return errors.New("sandbox tmpfs policy differs")
	}
	for path, size := range map[string]string{"/tmp": "size=64m", "/campaign": "size=128m", "/app/data": "size=1m", "/app/keys": "size=1m"} {
		options, ok := h.Tmpfs[path]
		if !ok {
			return fmt.Errorf("missing sandbox tmpfs policy %q", path)
		}
		for _, required := range []string{"nosuid", "nodev", "noexec", "uid=10001", "gid=10001", "mode=0700", size} {
			if !contains(strings.Split(options, ","), required) {
				return fmt.Errorf("sandbox tmpfs %q lacks %q", path, required)
			}
		}
	}
	artifactOptions, ok := h.Tmpfs["/artifacts"]
	if !ok {
		return errors.New("missing sandbox artifacts tmpfs")
	}
	for _, required := range []string{"rw", "nosuid", "nodev", "noexec", "size=64m", "uid=0", "gid=0", "mode=0755"} {
		if !contains(strings.Split(artifactOptions, ","), required) {
			return fmt.Errorf("sandbox artifacts tmpfs lacks %q", required)
		}
	}
	for _, mount := range info.Mounts {
		if mount.Type != "tmpfs" || (mount.Destination != "/tmp" && mount.Destination != "/campaign" && mount.Destination != "/artifacts" && mount.Destination != "/app/data" && mount.Destination != "/app/keys") {
			return fmt.Errorf("unapproved sandbox mount %q (%s)", mount.Destination, mount.Type)
		}
	}
	return nil
}

func (d *DockerEngine) Remove(ctx context.Context, id string) error {
	if !containerID.MatchString(id) {
		return errors.New("invalid container ID")
	}
	_, err := d.runner.Run(ctx, "rm", "-f", "-v", id)
	return err
}
