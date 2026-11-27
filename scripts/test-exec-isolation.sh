#!/bin/sh
# Test-only Go launcher for disposable Linux containers. Root isolation tests
# drop to the executor UID and re-execute the Go test binary; Go's temporary
# build directories otherwise block traversal before ARTEX's shim can run.
set -eu

if [ "$#" -lt 1 ]; then
    echo "missing Go test binary" >&2
    exit 2
fi

test_binary=$1
case "$test_binary" in
    /tmp/go-build*/*/*.test) ;;
    *) echo "unexpected Go test binary path" >&2; exit 2 ;;
esac

test_dir=$(dirname "$test_binary")
build_dir=$(dirname "$test_dir")
chmod o+x "$build_dir" "$test_dir"
chmod o+rx "$test_binary"
exec "$@"
