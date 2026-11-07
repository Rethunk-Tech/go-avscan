//go:build !linux

package avscan

import "net"

// trustedPeer has no peer-credential lookup here; the path owner checked before dialling is all that guards the
// default list.
func trustedPeer(net.Conn) bool { return true }
