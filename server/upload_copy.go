package server

import (
	"context"
	"fmt"
	"io"
)

// copyUploadBounded enforces the parsed multipart size while streaming.
// A request cancellation is checked between bounded chunks.
func copyUploadBounded(ctx context.Context, dst io.Writer, src io.Reader, expected, limit int64) error {
	if expected < 0 || expected > limit {
		return fmt.Errorf("upload exceeds size limit")
	}
	buf := make([]byte, 32<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if written+int64(n) > expected || written+int64(n) > limit {
				return fmt.Errorf("upload exceeds declared size")
			}
			nw, err := dst.Write(buf[:n])
			written += int64(nw)
			if err != nil {
				return err
			}
			if nw != n {
				return io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if written != expected {
		return fmt.Errorf("incomplete upload")
	}
	return ctx.Err()
}
