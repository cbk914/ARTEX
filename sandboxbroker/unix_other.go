//go:build !linux

package sandboxbroker

import "errors"

func validateBrokerClientSocketPath(string) error {
	return errors.New("broker Unix socket requires Linux")
}
