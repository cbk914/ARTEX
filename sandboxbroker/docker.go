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
)

const (
	sandboxUser = "10001:10001"
	memoryLimit = int64(256 << 20)
	pidLimit    = int64(64)
	nanoCPUs    = int64(500_000_000)
)

var containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var containerName = regexp.MustCompile(`^artex-campaign-[a-f0-9]{32}$`)

type commandRunner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type cliRunner struct{ path string }

func (r cliRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, r.path, args...).CombinedOutput()
	if len(output) > 1<<20 {
		output = output[:1<<20]
	}
	if err != nil {
		return nil, fmt.Errorf("docker command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
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
	if !containerName.MatchString(spec.Name) || !pinnedImage.MatchString(spec.Image) {
		return "", errors.New("invalid sandbox spec")
	}
	args := []string{
		"create", "--pull=never", "--name", spec.Name,
		"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--user=" + sandboxUser, "--memory=256m", "--memory-swap=256m", "--cpus=0.5", "--pids-limit=64",
		"--ulimit=nofile=1024:1024",
		"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700",
		"--tmpfs=/campaign:rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=0700",
		"--tmpfs=/app/data:rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700",
		"--tmpfs=/app/keys:rw,nosuid,nodev,noexec,size=1m,uid=10001,gid=10001,mode=0700",
		"--env=HOME=/campaign", "--env=TMPDIR=/tmp", "--env=XDG_CONFIG_HOME=/campaign/.config",
		"--entrypoint=/bin/sh", spec.Image, "-c", "sleep infinity",
	}
	output, err := d.runner.Run(ctx, args...)
	if err != nil {
		// Docker may create a container before returning an error. Remove only our random name.
		cleanupCtx := context.WithoutCancel(ctx)
		_, cleanupErr := d.runner.Run(cleanupCtx, "rm", "-f", "-v", spec.Name)
		if cleanupErr != nil {
			return "", errors.Join(err, fmt.Errorf("cleanup failed for %s: %w", spec.Name, cleanupErr))
		}
		return "", err
	}
	id := strings.TrimSpace(string(output))
	if !containerID.MatchString(id) {
		_, cleanupErr := d.runner.Run(context.WithoutCancel(ctx), "rm", "-f", "-v", spec.Name)
		return "", errors.Join(errors.New("docker returned invalid container ID"), cleanupErr)
	}
	return id, nil
}

func (d *DockerEngine) Start(ctx context.Context, id string) error {
	if !containerID.MatchString(id) {
		return errors.New("invalid container ID")
	}
	_, err := d.runner.Run(ctx, "start", id)
	return err
}

type containerInfo struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		User string   `json:"User"`
		Env  []string `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode    string            `json:"NetworkMode"`
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		CapAdd         []string          `json:"CapAdd"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		Memory         int64             `json:"Memory"`
		MemorySwap     int64             `json:"MemorySwap"`
		PidsLimit      int64             `json:"PidsLimit"`
		NanoCpus       int64             `json:"NanoCpus"`
		Binds          []string          `json:"Binds"`
		Tmpfs          map[string]string `json:"Tmpfs"`
		Privileged     bool              `json:"Privileged"`
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

func (d *DockerEngine) Verify(ctx context.Context, id string, spec Spec) error {
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
	if info.ID != id || info.Name != "/"+spec.Name || info.Image != image.ID || !info.State.Running || info.Config.User != sandboxUser ||
		h.NetworkMode != "none" || !h.ReadonlyRootfs || h.Privileged || len(h.CapAdd) != 0 || !contains(h.CapDrop, "ALL") ||
		!contains(h.SecurityOpt, "no-new-privileges:true") || h.Memory != memoryLimit || h.MemorySwap != memoryLimit ||
		h.PidsLimit != pidLimit || h.NanoCpus != nanoCPUs || len(h.Binds) != 0 || len(info.NetworkSettings.Networks) != 1 {
		return errors.New("sandbox container violates fixed isolation policy")
	}
	if _, onlyNone := info.NetworkSettings.Networks["none"]; !onlyNone {
		return errors.New("sandbox joined an unapproved network")
	}
	if len(h.Tmpfs) != 4 {
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
	for _, mount := range info.Mounts {
		if mount.Type != "tmpfs" || (mount.Destination != "/tmp" && mount.Destination != "/campaign" && mount.Destination != "/app/data" && mount.Destination != "/app/keys") {
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
