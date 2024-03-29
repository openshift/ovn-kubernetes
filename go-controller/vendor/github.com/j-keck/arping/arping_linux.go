package arping

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

type LinuxSocket struct {
	sock       int
	toSockaddr syscall.SockaddrLinklayer
}

func initialize(iface net.Interface) (s *LinuxSocket, err error) {
	s = &LinuxSocket{}
	s.toSockaddr = syscall.SockaddrLinklayer{Ifindex: iface.Index}

	// 1544 = htons(ETH_P_ARP)
	const proto = 1544
	s.sock, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	return s, err
}

func (s *LinuxSocket) send(request arpDatagram) (time.Time, error) {
	socketTimeout := timeout.Nanoseconds()
	t := syscall.NsecToTimeval(socketTimeout)
	syscall.SetsockoptTimeval(s.sock, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &t)
	return time.Now(), syscall.Sendto(s.sock, request.MarshalWithEthernetHeader(), 0, &s.toSockaddr)
}

func (s *LinuxSocket) receive() (arpDatagram, time.Time, error) {
	buffer := make([]byte, 128)
	socketTimeout := timeout.Nanoseconds()
	t := syscall.NsecToTimeval(socketTimeout)
	syscall.SetsockoptTimeval(s.sock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &t)
	n, _, err := syscall.Recvfrom(s.sock, buffer, 0)
	if err != nil {
		return arpDatagram{}, time.Now(), err
	}
	if n <= 14 {
		// amount of bytes read by socket is less than an ethernet header. clearly not what we look for
		return arpDatagram{}, time.Now(), fmt.Errorf("buffer with invalid length")

	}
	// skip 14 bytes ethernet header
	return parseArpDatagram(buffer[14:n]), time.Now(), nil
}

func (s *LinuxSocket) deinitialize() error {
	return syscall.Close(s.sock)
}
