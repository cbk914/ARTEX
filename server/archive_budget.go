package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const mib = int64(1 << 20)

type archiveBudget struct {
	compressed int64
	expanded   int64
	file       int64
	manifest   int64
	traffic    int64
	entries    int
	depth      int
}

func archiveMiBLimit(name string, fallback, hard int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback * mib, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 || n > hard {
		return 0, fmt.Errorf("%s must be between 1 and %d MiB", name, hard)
	}
	return n * mib, nil
}

func archiveCountLimit(name string, fallback, hard int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > hard {
		return 0, fmt.Errorf("%s must be between 1 and %d", name, hard)
	}
	return n, nil
}

func configuredArchiveBudget() (archiveBudget, error) {
	var b archiveBudget
	var err error
	if b.compressed, err = archiveMiBLimit("ARTEX_ARCHIVE_MAX_COMPRESSED_MIB", 8192, 32768); err != nil {
		return b, err
	}
	if b.expanded, err = archiveMiBLimit("ARTEX_ARCHIVE_MAX_EXPANDED_MIB", 16384, 65536); err != nil {
		return b, err
	}
	if b.file, err = archiveMiBLimit("ARTEX_ARCHIVE_MAX_FILE_MIB", 4096, 32768); err != nil {
		return b, err
	}
	if b.manifest, err = archiveMiBLimit("ARTEX_ARCHIVE_MAX_MANIFEST_MIB", 32, 128); err != nil {
		return b, err
	}
	if b.traffic, err = archiveMiBLimit("ARTEX_ARCHIVE_MAX_TRAFFIC_MIB", 256, 4096); err != nil {
		return b, err
	}
	if strings.TrimSpace(os.Getenv("ARTEX_ARCHIVE_MAX_TRAFFIC_MIB")) == "" && b.traffic > b.file {
		b.traffic = b.file
	}
	if b.entries, err = archiveCountLimit("ARTEX_ARCHIVE_MAX_ENTRIES", 100000, 250000); err != nil {
		return b, err
	}
	if b.depth, err = archiveCountLimit("ARTEX_ARCHIVE_MAX_DEPTH", 64, 128); err != nil {
		return b, err
	}
	if b.file > b.expanded || b.manifest > b.file || b.traffic > b.file {
		return b, errors.New("archive file, manifest and traffic limits must not exceed their parent limits")
	}
	return b, nil
}

func archivePathDepth(path string) int {
	return strings.Count(strings.ReplaceAll(path, `\`, "/"), "/") + 1
}

var errArchiveBudget = errors.New("task archive exceeds configured resource limits")

// archiveLimitWriter rejects a write before any part of it crosses the ceiling.
type archiveLimitWriter struct {
	out          io.Writer
	written, max int64
}

func (w *archiveLimitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.max-w.written {
		return 0, errArchiveBudget
	}
	n, err := w.out.Write(p)
	w.written += int64(n)
	return n, err
}
