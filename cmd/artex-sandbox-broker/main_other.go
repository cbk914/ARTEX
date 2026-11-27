//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ARTEX sandbox broker requires Linux")
	os.Exit(1)
}
