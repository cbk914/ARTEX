package sandboxbroker

import (
	"context"
	"strings"
	"testing"
)

func uploadVolumeSpec() Spec {
	return Spec{Name: "artex-campaign-" + strings.Repeat("a", 32), Image: testImage, Token: strings.Repeat("b", 64), Owner: strings.Repeat("c", 32)}
}

func uploadVolumeInspect(t *testing.T, spec Spec, labels map[string]string) []byte {
	t.Helper()
	name, err := uploadVolumeName(spec)
	if err != nil {
		t.Fatal(err)
	}
	return jsonArray(t, map[string]any{"Name": name, "Driver": "local", "Scope": "local", "Labels": labels, "Options": map[string]string{}})
}

func TestUploadVolumeLifecycleRequiresOwnership(t *testing.T) {
	spec := uploadVolumeSpec()
	name, _ := uploadVolumeName(spec)
	r := &recordingRunner{responses: map[string][]byte{"volume": uploadVolumeInspect(t, spec, map[string]string{ownershipLabel: spec.Token, ownerLabel: spec.Owner})}}
	d := &DockerEngine{runner: r}
	got, err := d.CreateUploadVolume(context.Background(), spec)
	if err != nil || got != name {
		t.Fatalf("create upload volume = %q, %v", got, err)
	}
	if err := d.RemoveUploadVolume(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 4 || !contains(r.calls[0], "--driver=local") || !contains(r.calls[0], "--label="+ownershipLabel+"="+spec.Token) || !contains(r.calls[0], "--label="+ownerLabel+"="+spec.Owner) || r.calls[0][len(r.calls[0])-1] != name || r.calls[3][1] != "rm" || r.calls[3][2] != name {
		t.Fatalf("unexpected volume lifecycle calls: %v", r.calls)
	}
}

func TestUploadVolumeNeverRemovesForeignOrAlteredVolume(t *testing.T) {
	spec := uploadVolumeSpec()
	for _, tc := range []struct {
		name    string
		labels  map[string]string
		options map[string]string
	}{
		{"foreign token", map[string]string{ownershipLabel: strings.Repeat("d", 64), ownerLabel: spec.Owner}, nil},
		{"foreign owner", map[string]string{ownershipLabel: spec.Token, ownerLabel: strings.Repeat("e", 32)}, nil},
		{"extra label", map[string]string{ownershipLabel: spec.Token, ownerLabel: spec.Owner, "unexpected": "value"}, nil},
		{"driver options", map[string]string{ownershipLabel: spec.Token, ownerLabel: spec.Owner}, map[string]string{"type": "nfs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, _ := uploadVolumeName(spec)
			info := map[string]any{"Name": name, "Driver": "local", "Scope": "local", "Labels": tc.labels, "Options": tc.options}
			r := &recordingRunner{responses: map[string][]byte{"volume": jsonArray(t, info)}}
			d := &DockerEngine{runner: r}
			if err := d.RemoveUploadVolume(context.Background(), spec); err == nil {
				t.Fatal("removed volume without matching ownership and policy")
			}
			if len(r.calls) != 1 || r.calls[0][1] != "inspect" {
				t.Fatalf("unexpected Docker calls: %v", r.calls)
			}
		})
	}
}

func TestUploadVolumeCreateCollisionDoesNotDeleteForeignVolume(t *testing.T) {
	spec := uploadVolumeSpec()
	name, _ := uploadVolumeName(spec)
	foreign := map[string]string{ownershipLabel: strings.Repeat("d", 64), ownerLabel: spec.Owner}
	r := &recordingRunner{responses: map[string][]byte{"volume": uploadVolumeInspect(t, spec, foreign)}}
	d := &DockerEngine{runner: r}
	if _, err := d.CreateUploadVolume(context.Background(), spec); err == nil {
		t.Fatal("accepted pre-existing foreign volume")
	}
	if len(r.calls) != 2 || r.calls[0][1] != "create" || r.calls[1][1] != "inspect" || r.calls[1][2] != name {
		t.Fatalf("unexpected Docker calls after foreign volume collision: %v", r.calls)
	}
}

func TestUploadVolumeRejectsInvalidSpecBeforeDocker(t *testing.T) {
	spec := uploadVolumeSpec()
	spec.Name = "artex-campaign-../foreign"
	r := &recordingRunner{}
	d := &DockerEngine{runner: r}
	if _, err := d.CreateUploadVolume(context.Background(), spec); err == nil {
		t.Fatal("accepted invalid volume spec")
	}
	if len(r.calls) != 0 {
		t.Fatalf("Docker called for invalid spec: %v", r.calls)
	}
}
