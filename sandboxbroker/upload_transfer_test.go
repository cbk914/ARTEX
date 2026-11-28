package sandboxbroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestDockerUploadUsesOwnedNetworklessHelperAndBoundedStdin(t *testing.T) {
	spec := uploadVolumeSpec()
	spec.UploadVolume = true
	volume, _ := uploadVolumeName(spec)
	helper, _ := uploadHelperName(spec)
	body := []byte("synthetic upload")
	digest := sha256.Sum256(body)
	r := &recordingRunner{responses: map[string][]byte{
		"image":          jsonArray(t, map[string]any{"Id": testImage}),
		"volume inspect": uploadVolumeInspect(t, spec, map[string]string{ownershipLabel: spec.Token, ownerLabel: spec.Owner}),
	}}
	d := &DockerEngine{runner: r}
	if err := d.PutUpload(context.Background(), spec, "fixture.txt", bytes.NewReader(body), int64(len(body)), fmt.Sprintf("%x", digest)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.input, body) || len(r.calls) != 4 {
		t.Fatalf("unexpected helper calls or input: calls=%v bytes=%d", r.calls, len(r.input))
	}
	args := r.calls[2]
	for _, expected := range []string{"--rm", "-i", "--pull=never", "--name=" + helper, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount=type=volume,src=" + volume + ",dst=/uploads", "--label=" + ownershipLabel + "=" + spec.Token, "--label=" + ownerLabel + "=" + spec.Owner, "--label=" + uploadHelperLabel + "=upload"} {
		if !contains(args, expected) {
			t.Errorf("missing helper policy argument %q", expected)
		}
	}
	if !strings.Contains(args[len(args)-6], "sha256sum -c") || args[len(args)-5] != "--" || args[len(args)-3] != "/uploads/fixture.txt" {
		t.Fatalf("unexpected upload publication command: %v", args)
	}
}

func TestDockerUploadRejectsMalformedRequestBeforeDocker(t *testing.T) {
	spec := uploadVolumeSpec()
	spec.UploadVolume = true
	r := &recordingRunner{}
	d := &DockerEngine{runner: r}
	if err := d.PutUpload(context.Background(), spec, "../escape", strings.NewReader("data"), 4, strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted upload path traversal")
	}
	if err := d.PutUpload(context.Background(), spec, "fixture", strings.NewReader("data"), maxCampaignUploadBytes+1, strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted upload beyond file limit")
	}
	if len(r.calls) != 0 {
		t.Fatalf("invalid request reached Docker: %v", r.calls)
	}
}

func TestUploadHelperRemovalPreservesForeignContainer(t *testing.T) {
	spec := uploadVolumeSpec()
	spec.UploadVolume = true
	helper, _ := uploadHelperName(spec)
	id := strings.Repeat("d", 64)
	r := &recordingRunner{responses: map[string][]byte{
		"ps upload helper": []byte(id + "\n"),
		"inspect":          jsonArray(t, map[string]any{"Id": id, "Name": "/" + helper, "Config": map[string]any{"Labels": map[string]string{ownershipLabel: strings.Repeat("e", 64), ownerLabel: spec.Owner, uploadHelperLabel: "upload"}}}),
	}}
	d := &DockerEngine{runner: r}
	if err := d.RemoveUploadHelper(context.Background(), spec); err == nil {
		t.Fatal("removed foreign upload helper")
	}
	if len(r.calls) != 2 {
		t.Fatalf("foreign helper was removed: %v", r.calls)
	}
}
