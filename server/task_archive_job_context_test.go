package server

import (
	"context"
	"errors"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
)

func TestArchiveJobEntrypointsStopOnExpiredContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &Server{}
	job := &pgdb.TaskArchive{}
	if err := s.archiveTask(ctx, job); !errors.Is(err, context.Canceled) {
		t.Fatalf("archive accepted expired job context: %v", err)
	}
	if err := s.restoreTaskArchive(ctx, job); !errors.Is(err, context.Canceled) {
		t.Fatalf("restore accepted expired job context: %v", err)
	}
	if err := s.deleteTaskArchive(ctx, job); !errors.Is(err, context.Canceled) {
		t.Fatalf("delete accepted expired job context: %v", err)
	}
}
