//go:build linux

package avscan

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The connected socket's peer, not the path, decides: a listener this user runs is refused unless this user is root.
func TestTrustedPeerReadsTheConnectedSocketsOwner(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if got, want := trustedPeer(conn), os.Geteuid() == 0; got != want {
		t.Fatalf("trustedPeer = %v, want %v", got, want)
	}
	if trustedPeer(nil2()) {
		t.Fatal("a non-unix connection was trusted")
	}
}

func nil2() net.Conn { c, _ := net.Pipe(); return c }
