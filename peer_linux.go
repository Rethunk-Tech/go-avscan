//go:build linux

package avscan

import (
	"net"

	"golang.org/x/sys/unix"
)

// trustedPeer reports whether the process on the other end of a default-list socket runs as root or the clamav user.
// The path's owner can change between the stat and the dial; the peer credentials of the connected socket cannot.
func trustedPeer(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return false
	}
	return trustedUID(cred.Uid)
}
