package server

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// openTaskRunRoot walks only the fixed task run-directory layout beneath the
// server data root. Each component must be a real directory and the opened
// descriptor must still be the directory inspected before opening it.
func openTaskRunRoot(dataDir string, taskID int64) (*os.Root, error) {
	if taskID <= 0 {
		return nil, errors.New("invalid task upload root")
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"tasks", strconv.FormatInt(taskID, 10), "main"} {
		selected, err := root.Lstat(name)
		if err != nil || !selected.IsDir() {
			root.Close()
			return nil, fmt.Errorf("unsafe task upload directory %q", name)
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			root.Close()
			return nil, err
		}
		opened, err := child.Open(".")
		if err != nil {
			child.Close()
			root.Close()
			return nil, err
		}
		actual, statErr := opened.Stat()
		closeErr := opened.Close()
		if err := errors.Join(statErr, closeErr); err != nil || !os.SameFile(selected, actual) {
			child.Close()
			root.Close()
			return nil, fmt.Errorf("task upload directory %q changed at open", name)
		}
		root.Close()
		root = child
	}
	return root, nil
}
