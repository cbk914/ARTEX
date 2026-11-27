package db

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestTaskArchiveTransactionsRejectExpiredJobContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &DB{}
	if _, err := d.SnapshotTaskArchiveWithLLMRecordsContext(ctx, 1, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("snapshot accepted expired context: %v", err)
	}
	if err := d.CompleteTaskArchiveContext(ctx, 1, nil, "", "", 0, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("compaction accepted expired context: %v", err)
	}
	if _, err := d.RestoreTaskArchiveContext(ctx, 1, nil, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("restore accepted expired context: %v", err)
	}
	if err := d.CompleteTaskArchiveRestoreContext(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("restore completion accepted expired context: %v", err)
	}
	if err := d.DeleteTaskArchiveStubContext(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("archive deletion accepted expired context: %v", err)
	}
}
