package traffic

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Legacy exchange files were written before bodies moved into SQLite and the
// content-addressed blob store. These reads still need a bounded root.
const maxLegacyExchangeFile = int64(64 << 20)

func (t *Traffic) readLegacyExchangeFile(relativeDir, name string) ([]byte, error) {
	if !filepath.IsLocal(relativeDir) || filepath.Clean(relativeDir) == "." || (name != "request.http" && name != "response.http") {
		return nil, errors.New("unsafe legacy traffic path")
	}
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	relative := filepath.Join(relativeDir, name)
	selected, err := root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // Historical captures may lack one side.
	}
	if err != nil {
		return nil, err
	}
	if !selected.Mode().IsRegular() || selected.Size() < 0 || selected.Size() > maxLegacyExchangeFile {
		return nil, errors.New("legacy traffic file is unsafe or exceeds its limit")
	}
	file, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(selected, opened) || opened.Size() != selected.Size() {
		return nil, errors.New("legacy traffic file changed at open")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxLegacyExchangeFile+1))
	if err != nil {
		return nil, err
	}
	final, err := file.Stat()
	if err != nil || int64(len(data)) != selected.Size() || !os.SameFile(selected, final) || final.Size() != selected.Size() || !final.ModTime().Equal(selected.ModTime()) {
		return nil, fmt.Errorf("legacy traffic file changed during read: %s", name)
	}
	return data, nil
}
