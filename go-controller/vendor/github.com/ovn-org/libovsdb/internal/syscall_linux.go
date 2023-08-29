package internal

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"
)

// SetTCPUserTimeout sets the TCP user timeout on a connection's socket
func SetTCPUserTimeout(logger *logr.Logger, conn net.Conn, timeout time.Duration) error {
	tcpconn, ok := conn.(*net.TCPConn)
	if !ok {
		// not a TCP connection. exit early
		return nil
	}
	logger.V(3).Info("tcp user timeout to be set")
	rawConn, err := tcpconn.SyscallConn()
	if err != nil {
		return fmt.Errorf("error getting raw connection: %v", err)
	}
	err = rawConn.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(timeout/time.Millisecond))
	})
	if err != nil {
		return fmt.Errorf("error setting option on socket: %v", err)
	}
	logger.V(3).Info("tcp user timeout is set")
	return nil
}
