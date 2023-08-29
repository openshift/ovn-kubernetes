//go:build !linux
// +build !linux

package internal

import (
	"net"
	"time"

	"github.com/go-logr/logr"
)

// SetTCPUserTimeout is a no-op function under non-linux environments.
func SetTCPUserTimeout(logger *logr.Logger, conn net.Conn, timeout time.Duration) error {
	return nil
}
