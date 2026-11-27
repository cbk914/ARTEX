//go:build unix

package sandboxbroker

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDockerExecWrapperShellContract(t *testing.T) {
	marker := "synthetic-status-marker"
	cmd := exec.Command("/bin/sh", "-c", dockerExecWrapper, "--", "printf diagnostic; exit 7", marker)
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != "diagnostic\n"+marker+":7\n" {
		t.Fatalf("wrapped command = %q, %v", output, err)
	}
	cmd = exec.Command("/bin/sh", "-c", dockerExecWrapper, "--", "cat; exit 9", marker)
	cmd.Stdin = strings.NewReader("stdin")
	output, err = cmd.CombinedOutput()
	if err != nil || string(output) != "stdin\n"+marker+":9\n" {
		t.Fatalf("wrapped stdin command = %q, %v", output, err)
	}
}
