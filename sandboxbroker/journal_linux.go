//go:build linux

package sandboxbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// FileJournal is a root-only, write-ahead creation-intent ledger. Its caller
// must hold BrokerIdentity's exclusive lock for the journal's lifetime.
type FileJournal struct {
	dir   string
	owner string
}

func (i *BrokerIdentity) OpenJournal() (*FileJournal, error) {
	if i == nil || i.lock == nil || !brokerOwner.MatchString(i.Owner) {
		return nil, errors.New("broker identity lock is required")
	}
	dir := filepath.Join(filepath.Dir(i.lock.Name()), "broker-journal")
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("broker journal directory must be root-owned mode 0700")
	}
	return &FileJournal{dir: dir, owner: i.Owner}, nil
}

func (j *FileJournal) path(spec Spec) (string, error) {
	if j == nil || !containerName.MatchString(spec.Name) || !pinnedImage.MatchString(spec.Image) || !ownershipToken.MatchString(spec.Token) || spec.Owner != j.owner {
		return "", errors.New("invalid broker journal spec")
	}
	return filepath.Join(j.dir, spec.Name+".json"), nil
}

func (j *FileJournal) syncDir() error {
	f, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	return errors.Join(err, f.Close())
}

func (j *FileJournal) Record(spec Spec) error {
	path, err := j.path(spec)
	if err != nil {
		return err
	}
	data, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	f, err := openPrivateFile(path, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close(), j.syncDir())
}

func (j *FileJournal) read(path string) (Spec, error) {
	f, err := openPrivateFile(path, syscall.O_RDONLY)
	if err != nil {
		return Spec{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 1024))
	err = errors.Join(readErr, f.Close())
	if err != nil {
		return Spec{}, err
	}
	var spec Spec
	if len(data) == 0 || len(data) >= 1024 || json.Unmarshal(data, &spec) != nil {
		return Spec{}, errors.New("invalid broker journal record")
	}
	if _, err := j.path(spec); err != nil || path != filepath.Join(j.dir, spec.Name+".json") {
		return Spec{}, errors.New("broker journal record identity mismatch")
	}
	return spec, nil
}

func (j *FileJournal) Forget(spec Spec) error {
	path, err := j.path(spec)
	if err != nil {
		return err
	}
	stored, err := j.read(path)
	if err != nil {
		return err
	}
	if stored != spec {
		return errors.New("broker journal record changed")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return j.syncDir()
}

// Entries fails closed on any malformed or unexpected file. Cleanup never
// guesses which Docker resource a damaged record might describe.
func (j *FileJournal) Entries() ([]Spec, error) {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, err
	}
	result := make([]Spec, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !containerName.MatchString(strings.TrimSuffix(entry.Name(), ".json")) {
			// The exact filename is checked again against the decoded record.
			return nil, fmt.Errorf("unexpected broker journal entry %q", entry.Name())
		}
		path := filepath.Join(j.dir, entry.Name())
		spec, err := j.read(path)
		if err != nil {
			return nil, fmt.Errorf("read broker journal entry %q: %w", entry.Name(), err)
		}
		result = append(result, spec)
	}
	return result, nil
}

// RecoverRecorded removes only containers with a journaled creation token,
// matching owner, name, image and fixed isolation policy. Unknown or altered
// resources stop startup and remain available for operator inspection.
func (d *DockerEngine) RecoverRecorded(ctx context.Context, j *FileJournal, image string) error {
	if j == nil || !pinnedImage.MatchString(image) {
		return errors.New("valid recovery journal and pinned image are required")
	}
	entries, err := j.Entries()
	if err != nil {
		return err
	}
	for _, spec := range entries {
		if spec.Image != image {
			return errors.New("journal image differs from configured sandbox image")
		}
		if spec.UploadVolume {
			if err := d.RemoveUploadHelper(ctx, spec); err != nil {
				return fmt.Errorf("remove journaled upload helper for %s: %w", spec.Name, err)
			}
		}
		output, err := d.runner.Run(ctx, "ps", "-a", "--no-trunc",
			"--filter=label="+ownershipLabel+"="+spec.Token,
			"--filter=label="+ownerLabel+"="+spec.Owner,
			"--format={{.ID}}")
		if err != nil {
			return fmt.Errorf("list journaled sandbox %s: %w", spec.Name, err)
		}
		ids := strings.Fields(string(output))
		if len(ids) == 0 {
			if spec.UploadVolume {
				if err := d.RemoveUploadVolume(ctx, spec); err != nil {
					return fmt.Errorf("remove orphaned upload volume for %s: %w", spec.Name, err)
				}
			}
			if err := j.Forget(spec); err != nil {
				return err
			}
			continue
		}
		if len(ids) != 1 || !containerID.MatchString(ids[0]) {
			return fmt.Errorf("ambiguous journaled sandbox %s", spec.Name)
		}
		if err := d.verify(ctx, ids[0], spec, false); err != nil {
			return fmt.Errorf("unsafe journaled sandbox %s: %w", spec.Name, err)
		}
		if err := d.Remove(ctx, ids[0]); err != nil {
			return fmt.Errorf("remove journaled sandbox %s: %w", spec.Name, err)
		}
		if spec.UploadVolume {
			if err := d.RemoveUploadVolume(ctx, spec); err != nil {
				return fmt.Errorf("remove journaled upload volume for %s: %w", spec.Name, err)
			}
		}
		if err := j.Forget(spec); err != nil {
			return err
		}
	}
	return nil
}
