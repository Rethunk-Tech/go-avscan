//go:build unix

package avscan

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// defaultSockets is process-wide, so this test does not run in parallel.
func TestClamdSkipsDefaultSocketOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the socket")
	}
	path := filepath.Join(t.TempDir(), "clamd.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	old := defaultSockets
	defaultSockets = []string{path}
	defer func() { defaultSockets = old }()
	if got := (Clamd{}).candidates(); len(got) != 0 {
		t.Fatalf("a socket owned by this user is trusted: %v", got)
	}
	if got := (Clamd{Socket: path}).candidates(); len(got) != 1 {
		t.Fatalf("a configured socket is trusted as given: %v", got)
	}
}

// A symlink in the folder must not lead the scan to a file outside it.
func TestScanSkipsSymlinks(t *testing.T) {
	t.Parallel()
	outside := writeTree(t, map[string]string{"bad.dll": eicar()})
	dir := writeTree(t, map[string]string{"a.dll": "fine"})
	if err := os.Symlink(filepath.Join(outside, "bad.dll"), filepath.Join(dir, "link.dll")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "dir")); err != nil {
		t.Fatal(err)
	}
	if got, found, err := fakeClamd(t, 0).Scan(t.Context(), dir); found || err != nil {
		t.Fatalf("a symlink was followed: %+v, %v", got, err)
	}
}
