package server

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
	"github.com/klauspost/compress/zstd"
)

func TestArchiveTrafficManifestBudgetTracksFileCeiling(t *testing.T) {
	t.Setenv("ARTEX_ARCHIVE_MAX_FILE_MIB", "1")
	t.Setenv("ARTEX_ARCHIVE_MAX_MANIFEST_MIB", "1")
	budget, err := configuredArchiveBudget()
	if err != nil || budget.traffic != 1<<20 {
		t.Fatalf("default traffic budget=%d err=%v", budget.traffic, err)
	}
	t.Setenv("ARTEX_ARCHIVE_MAX_TRAFFIC_MIB", "2")
	if _, err := configuredArchiveBudget(); err == nil {
		t.Fatal("accepted traffic manifest limit above one-file archive limit")
	}
	t.Setenv("ARTEX_ARCHIVE_MAX_TRAFFIC_MIB", "0")
	if _, err := configuredArchiveBudget(); err == nil {
		t.Fatal("accepted disabled traffic manifest limit")
	}
}

func TestArchiveBudgetRejectsCompressedInputBeforeExtraction(t *testing.T) {
	t.Setenv("ARTEX_ARCHIVE_MAX_COMPRESSED_MIB", "1")
	path := filepath.Join(t.TempDir(), "oversized.tar.zst")
	if err := os.WriteFile(path, make([]byte, 1<<20+1), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restore")
	if err := extractTaskArchivePackage(path, "", destination); !errors.Is(err, errArchiveBudget) {
		t.Fatalf("error=%v, want resource limit", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("created destination before rejecting package: %v", err)
	}
}

func TestArchiveBudgetRejectsExpandedHeaderAndDepth(t *testing.T) {
	t.Setenv("ARTEX_ARCHIVE_MAX_EXPANDED_MIB", "1")
	t.Setenv("ARTEX_ARCHIVE_MAX_FILE_MIB", "1")
	t.Setenv("ARTEX_ARCHIVE_MAX_MANIFEST_MIB", "1")
	for _, tc := range []struct {
		name, entry string
		size        int64
	}{
		{"expanded", "big.bin", 2 << 20},
		{"depth", strings.Repeat("nested/", 65) + "file.txt", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var compressed bytes.Buffer
			encoder, err := zstd.NewWriter(&compressed)
			if err != nil {
				t.Fatal(err)
			}
			tw := tar.NewWriter(encoder)
			if err := tw.WriteHeader(&tar.Header{Name: tc.entry, Mode: 0o600, Size: tc.size}); err != nil {
				t.Fatal(err)
			}
			_ = tw.Close() // An incomplete body is intentional for the oversized-header case.
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "fixture.tar.zst")
			if err := os.WriteFile(path, compressed.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := extractTaskArchivePackage(path, "", t.TempDir()); err == nil || !strings.Contains(err.Error(), "extraction safety limits") {
				t.Fatalf("error=%v, want safety limit", err)
			}
		})
	}
}

func TestArchiveBudgetRejectsCreationBeforePublishing(t *testing.T) {
	for _, tc := range []struct {
		name           string
		data           []byte
		setting, value string
	}{
		{"expanded file", make([]byte, 2<<20), "ARTEX_ARCHIVE_MAX_FILE_MIB", "1"},
		{"compressed output", randomArchiveBytes(t, 2<<20), "ARTEX_ARCHIVE_MAX_COMPRESSED_MIB", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.setting, tc.value)
			if tc.setting == "ARTEX_ARCHIVE_MAX_FILE_MIB" {
				t.Setenv("ARTEX_ARCHIVE_MAX_MANIFEST_MIB", "1")
			}
			payload := t.TempDir()
			if err := os.WriteFile(filepath.Join(payload, "data.bin"), tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "task.tar.zst")
			if _, _, _, err := writeTaskArchivePackage(path, payload, &pgdb.TaskArchiveSnapshot{}); !errors.Is(err, errArchiveBudget) {
				t.Fatalf("error=%v, want resource limit", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("published rejected archive: %v", err)
			}
			if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
				t.Fatalf("left partial archive: %v", err)
			}
		})
	}
}

func randomArchiveBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestArchiveBudgetRejectsUnsafeConfiguration(t *testing.T) {
	t.Setenv("ARTEX_ARCHIVE_MAX_EXPANDED_MIB", "65537")
	if _, err := configuredArchiveBudget(); err == nil {
		t.Fatal("accepted a value above the hard ceiling")
	}
}

func TestArchiveBudgetEntryCountAndReviewedOverride(t *testing.T) {
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(encoder)
	for _, name := range []string{"first.bin", "second.bin"} {
		content := make([]byte, 768<<10)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.tar.zst")
	if err := os.WriteFile(path, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_ARCHIVE_MAX_ENTRIES", "1")
	if err := extractTaskArchivePackage(path, "", t.TempDir()); err == nil || !strings.Contains(err.Error(), "extraction safety limits") {
		t.Fatalf("entry count error=%v", err)
	}
	t.Setenv("ARTEX_ARCHIVE_MAX_ENTRIES", "2")
	t.Setenv("ARTEX_ARCHIVE_MAX_EXPANDED_MIB", "1")
	t.Setenv("ARTEX_ARCHIVE_MAX_FILE_MIB", "1")
	t.Setenv("ARTEX_ARCHIVE_MAX_MANIFEST_MIB", "1")
	if err := extractTaskArchivePackage(path, "", t.TempDir()); err == nil || !strings.Contains(err.Error(), "extraction safety limits") {
		t.Fatalf("expanded size error=%v", err)
	}
	t.Setenv("ARTEX_ARCHIVE_MAX_EXPANDED_MIB", "2")
	destination := t.TempDir()
	if err := extractTaskArchivePackage(path, "", destination); err != nil {
		t.Fatalf("reviewed override rejected valid package: %v", err)
	}
	for _, name := range []string{"first.bin", "second.bin"} {
		info, err := os.Stat(filepath.Join(destination, name))
		if err != nil || info.Size() != 768<<10 {
			t.Fatalf("restored %s: %v, %v", name, info, err)
		}
	}
}

func TestArchiveBudgetRejectsOversizedManifest(t *testing.T) {
	t.Setenv("ARTEX_ARCHIVE_MAX_MANIFEST_MIB", "1")
	payload := t.TempDir()
	path := filepath.Join(t.TempDir(), "task.tar.zst")
	snapshot := &pgdb.TaskArchiveSnapshot{Hosts: []string{strings.Repeat("a", 1<<20)}}
	if _, _, _, err := writeTaskArchivePackage(path, payload, snapshot); !errors.Is(err, errArchiveBudget) {
		t.Fatalf("error=%v, want manifest budget", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("published rejected manifest: %v", err)
	}
}
