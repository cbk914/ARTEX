//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/sandboxbroker"
)

func main() {
	var dockerPath, image, socketPath string
	flag.StringVar(&dockerPath, "docker-path", "", "absolute path to the trusted Docker CLI")
	flag.StringVar(&image, "image", "", "reviewed, pinned sandbox image digest")
	flag.StringVar(&socketPath, "socket", "", "absolute path to broker.sock in a root-controlled directory")
	flag.Parse()
	if flag.NArg() != 0 || dockerPath == "" || image == "" || socketPath == "" {
		fmt.Fprintln(os.Stderr, "docker-path, image and socket are required; positional arguments are forbidden")
		os.Exit(2)
	}
	engine, err := sandboxbroker.NewDockerEngine(dockerPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	identity, err := sandboxbroker.OpenBrokerIdentity(socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer identity.Close()
	journal, err := identity.OpenJournal()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	recoveryCtx, cancelRecovery := context.WithTimeout(context.Background(), 2*time.Minute)
	err = engine.RecoverRecorded(recoveryCtx, journal, image)
	cancelRecovery()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := identity.PrepareSocket(socketPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	broker, err := sandboxbroker.NewWithJournal(engine, image, identity.Owner, journal)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := sandboxbroker.ServeUnix(ctx, socketPath, broker); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
