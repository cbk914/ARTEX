package sandboxbroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxCampaignUploadBytes = 512 << 20
const uploadHelperLabel = "org.artex.sandbox.helper"

var uploadDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func uploadHelperName(spec Spec) (string, error) {
	name, err := uploadVolumeName(spec)
	if err != nil || !spec.UploadVolume {
		return "", errors.New("campaign upload volume is not enabled")
	}
	return strings.Replace(name, "artex-upload-", "artex-upload-seed-", 1), nil
}

// RemoveUploadHelper removes only the helper named by a journaled spec and
// carrying both random ownership labels. It is safe to retry after a crash.
func (d *DockerEngine) RemoveUploadHelper(ctx context.Context, spec Spec) error {
	name, err := uploadHelperName(spec)
	if err != nil {
		return err
	}
	output, err := d.runner.Run(ctx, "ps", "-a", "--no-trunc", "--filter=name=^/"+name+"$", "--format={{.ID}}")
	if err != nil {
		return err
	}
	ids := strings.Fields(string(output))
	if len(ids) == 0 {
		return nil
	}
	if len(ids) != 1 || !containerID.MatchString(ids[0]) {
		return errors.New("ambiguous campaign upload helper")
	}
	output, err = d.runner.Run(ctx, "inspect", ids[0])
	if err != nil {
		return err
	}
	info, err := decodeOne[containerInfo](output)
	if err != nil {
		return err
	}
	if info.ID != ids[0] || info.Name != "/"+name || info.Config.Labels[ownershipLabel] != spec.Token || info.Config.Labels[ownerLabel] != spec.Owner || info.Config.Labels[uploadHelperLabel] != "upload" {
		return errors.New("campaign upload helper ownership mismatch")
	}
	_, err = d.runner.Run(ctx, "rm", "-f", "-v", ids[0])
	return err
}

const publishUploadCommand = `set -eu
umask 077
mkdir -p -m 0700 /uploads/.incoming
test ! -e "$2"
cat > "$1"
test "$(wc -c < "$1")" -eq "$4"
printf '%s  %s\n' "$3" "$1" | sha256sum -c - >/dev/null
chmod 0444 "$1"
ln "$1" "$2"
rm "$1"`

// PutUpload streams one immutable file to a separate, networkless helper. The
// running sandbox sees the same volume read-only. The helper publishes only
// after exact length and SHA-256 checks; a partial stage stays root-private.
func (d *DockerEngine) PutUpload(ctx context.Context, spec Spec, name string, input io.Reader, size int64, digest string) error {
	if !spec.UploadVolume || !validArtifactName(name) || input == nil || size <= 0 || size > maxCampaignUploadBytes || !uploadDigest.MatchString(digest) {
		return errors.New("invalid campaign upload")
	}
	if err := d.CheckImage(ctx, spec.Image); err != nil {
		return err
	}
	if err := d.VerifyUploadVolume(ctx, spec); err != nil {
		return err
	}
	helper, _ := uploadHelperName(spec)
	volume, _ := uploadVolumeName(spec)
	stageID, err := randomHex(16)
	if err != nil {
		return err
	}
	stage := "/uploads/.incoming/" + stageID
	final := "/uploads/" + name
	args := []string{
		"run", "--rm", "-i", "--pull=never", "--name=" + helper,
		"--label=" + ownershipLabel + "=" + spec.Token,
		"--label=" + ownerLabel + "=" + spec.Owner,
		"--label=" + uploadHelperLabel + "=upload",
		"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--user=0:0", "--memory=768m", "--memory-swap=768m", "--cpus=0.5", "--pids-limit=32",
		"--mount=type=volume,src=" + volume + ",dst=/uploads",
		"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m",
		"--tmpfs=/app/data:rw,nosuid,nodev,noexec,size=1m",
		"--tmpfs=/app/keys:rw,nosuid,nodev,noexec,size=1m",
		"--entrypoint=/bin/sh", spec.Image, "-c", publishUploadCommand, "--", stage, final, digest, strconv.FormatInt(size, 10),
	}
	_, runErr := d.runner.RunInput(ctx, io.LimitReader(input, size+1), args...)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cleanupErr := d.RemoveUploadHelper(cleanupCtx, spec)
	if runErr != nil || cleanupErr != nil {
		if runErr != nil {
			runErr = fmt.Errorf("publish campaign upload: %w", runErr)
		}
		return errors.Join(runErr, cleanupErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
