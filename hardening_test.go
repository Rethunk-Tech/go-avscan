package avscan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
)

func TestAMSIFlaggedCountsDetectionsAndAdminBlocks(t *testing.T) {
	t.Parallel()
	for result, want := range map[uint32]bool{
		0: false, 1: false, 0x3FFF: false, 0x4000: true, 0x4800: true, 0x4FFF: true, 0x5000: false,
		32767: false, 32768: true, 0xFFFFFFFF: true,
	} {
		if got := amsiFlagged(result); got != want {
			t.Errorf("amsiFlagged(%#x) = %v, want %v", result, got, want)
		}
	}
}

func TestAMSIViewOverlapsChunksAndCoversEveryByte(t *testing.T) {
	t.Parallel()
	const chunk, overlap = 10, 4
	data := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	v := newAMSIView(bytes.NewReader(data), int64(len(data)), chunk, overlap)
	var windows []string
	var fresh []byte
	for {
		buf, err := v.next()
		if len(buf) > 0 {
			windows = append(windows, string(buf))
			keep := 0
			if len(fresh) > 0 {
				keep = overlap
			}
			fresh = append(fresh, buf[keep:]...)
		}
		if err != nil {
			break
		}
	}
	if !bytes.Equal(fresh, data) {
		t.Fatalf("new bytes %q, want %q", fresh, data)
	}
	if len(windows) != 4 || !strings.HasPrefix(windows[1], "6789") {
		t.Fatalf("windows = %q", windows)
	}
	if empty := newAMSIView(strings.NewReader(""), 0, chunk, overlap); func() bool { b, err := empty.next(); return len(b) != 0 || !errors.Is(err, io.EOF) }() {
		t.Fatal("an empty file has no window")
	}
	if small := newAMSIView(strings.NewReader("ab"), 2, 1<<20, 1<<20); len(small.buf) != 1<<20+2 {
		t.Fatalf("a small file costs %d bytes", len(small.buf))
	}
}

func TestCleanNameBoundsAndStripsControls(t *testing.T) {
	t.Parallel()
	if got := cleanName("  Win.Bad\x1b[31m\r\n "); got != "Win.Bad[31m" {
		t.Fatalf("got %q", got)
	}
	long := cleanName(strings.Repeat("é", 1000))
	if len(long) > maxNameLen || strings.ContainsRune(long, '�') {
		t.Fatalf("len %d, %q", len(long), long[len(long)-4:])
	}
}

func TestACancelledDialIsNotNoScanner(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := Clamd{Dial: func(ctx context.Context) (net.Conn, error) { return nil, ctx.Err() }}
	if _, err := c.Version(ctx); !errors.Is(err, context.Canceled) || errors.Is(err, ErrNoScanner) {
		t.Fatalf("err = %v", err)
	}
}

func TestCommandOutputIsBoundedAndNameCapped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	t.Parallel()
	dir := writeTree(t, map[string]string{"a.dll": "x"})
	line := `sh -c "printf '%0300d\n' 0; yes | head -c 20000000; exit 1" {path}`
	got, found, err := Command{Line: line}.Scan(t.Context(), dir)
	if err != nil || !found || got.Name != strings.Repeat("0", maxNameLen) {
		t.Fatalf("detection = %d bytes %v, %v", len(got.Name), found, err)
	}
}
