//go:build unix

package avscan

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// defaultSockets is process-wide, so this test does not run in parallel.
func TestClamdSkipsDefaultSocketOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the socket")
	}
	path := filepath.Join(t.TempDir(), "clamd.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
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

func TestUnreadableDefaultSocketIsNotTrusted(t *testing.T) {
	t.Parallel()
	if trustedSocketOwner(filepath.Join(t.TempDir(), "gone.sock")) {
		t.Fatal("a socket that cannot be stat'ed was trusted")
	}
}

// A FIFO swapped in after the walk must be skipped, not waited on.
func TestOpenRegularSkipsAFIFO(t *testing.T) {
	t.Parallel()
	dir := writeTree(t, map[string]string{"a": "x"})
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := openRegular(root, "pipe"); !errors.Is(err, errNotRegular) {
		t.Fatalf("err = %v", err)
	}
	f, err := openRegular(root, "a")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}
