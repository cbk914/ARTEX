package sandboxbroker

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// uploadVolumeName binds an attachment volume to the same random identity as
// its campaign container. The name alone never proves ownership.
func uploadVolumeName(spec Spec) (string, error) {
	if !containerName.MatchString(spec.Name) || !ownershipToken.MatchString(spec.Token) || !brokerOwner.MatchString(spec.Owner) || !pinnedImage.MatchString(spec.Image) {
		return "", errors.New("invalid campaign upload volume spec")
	}
	return "artex-upload-" + strings.TrimPrefix(spec.Name, "artex-campaign-"), nil
}

type uploadVolumeInfo struct {
	Name    string            `json:"Name"`
	Driver  string            `json:"Driver"`
	Scope   string            `json:"Scope"`
	Labels  map[string]string `json:"Labels"`
	Options map[string]string `json:"Options"`
}

// VerifyUploadVolume refuses to infer ownership from a Docker volume name.
// The token and installation owner must both match the journaled sandbox spec.
func (d *DockerEngine) VerifyUploadVolume(ctx context.Context, spec Spec) error {
	name, err := uploadVolumeName(spec)
	if err != nil {
		return err
	}
	output, err := d.runner.Run(ctx, "volume", "inspect", name)
	if err != nil {
		return fmt.Errorf("inspect campaign upload volume: %w", err)
	}
	info, err := decodeOne[uploadVolumeInfo](output)
	if err != nil {
		return err
	}
	if info.Name != name || info.Driver != "local" || info.Scope != "local" || len(info.Options) != 0 || len(info.Labels) != 2 || info.Labels[ownershipLabel] != spec.Token || info.Labels[ownerLabel] != spec.Owner {
		return errors.New("campaign upload volume violates ownership policy")
	}
	return nil
}

// CreateUploadVolume creates only an empty, labelled local volume. Callers
// must journal the spec first and retain it until volume and container removal
// have both completed. This operation does not publish attachments.
func (d *DockerEngine) CreateUploadVolume(ctx context.Context, spec Spec) (string, error) {
	name, err := uploadVolumeName(spec)
	if err != nil {
		return "", err
	}
	_, err = d.runner.Run(ctx, "volume", "create", "--driver=local", "--label="+ownershipLabel+"="+spec.Token, "--label="+ownerLabel+"="+spec.Owner, name)
	if err != nil {
		return "", fmt.Errorf("create campaign upload volume: %w", err)
	}
	if err := d.VerifyUploadVolume(ctx, spec); err != nil {
		return "", err
	}
	return name, nil
}

// RemoveUploadVolume never deletes a volume whose ownership cannot be fully
// attested. Docker itself refuses removal while any container still uses it.
func (d *DockerEngine) RemoveUploadVolume(ctx context.Context, spec Spec) error {
	name, err := uploadVolumeName(spec)
	if err != nil {
		return err
	}
	if err := d.VerifyUploadVolume(ctx, spec); err != nil {
		return err
	}
	_, err = d.runner.Run(ctx, "volume", "rm", name)
	return err
}
