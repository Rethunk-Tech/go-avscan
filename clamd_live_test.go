package avscan

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

// liveClamd needs a real daemon: AVSCAN_CLAMD_TCP=host:port. The fake in
// avscan_test.go proves only our reading of the protocol.
func liveClamd(t *testing.T) Clamd {
	t.Helper()
	addr := os.Getenv("AVSCAN_CLAMD_TCP")
	if addr == "" {
		t.Skip("AVSCAN_CLAMD_TCP not set")
	}
	return Clamd{Dial: func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
}

func TestLiveScanReaderFlagsEICARAndPassesClean(t *testing.T) {
	c := liveClamd(t)
	d, found, err := c.ScanReader(t.Context(), "upload.bin", strings.NewReader(eicar()))
	if err != nil || !found {
		t.Fatalf("eicar: found=%v err=%v", found, err)
	}
	if d.File != "upload.bin" || d.Scanner != "clamd" || !strings.Contains(strings.ToLower(d.Name), "eicar") {
		t.Fatalf("detection = %+v", d)
	}
	if _, found, err := c.ScanReader(t.Context(), "clean.txt", strings.NewReader("hello")); found || err != nil {
		t.Fatalf("clean: found=%v err=%v", found, err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestLiveScanReaderOverStreamLimitIsTooLarge(t *testing.T) {
	c := liveClamd(t)
	// Far over any default StreamMaxLength; clamd cuts it off well before the end.
	_, found, err := c.ScanReader(t.Context(), "big.bin", io.LimitReader(zeros{}, 8<<30))
	if found || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestLiveScanReaderUnreachableDaemonIsNoScanner(t *testing.T) {
	c := Clamd{Socket: t.TempDir() + "/absent.sock"}
	if _, _, err := c.ScanReader(t.Context(), "x", strings.NewReader("x")); !errors.Is(err, ErrNoScanner) {
		t.Fatalf("err = %v", err)
	}
}
