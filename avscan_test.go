package avscan

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// eicar is the standard antivirus test string, assembled at run time so no file in the repo holds it whole.
func eicar() string {
	return strings.Join([]string{`X5O!P%@AP[4\PZX54(P^)7CC)7}$`, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", `!$H+H*`}, "")
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeClamd answers like clamd: INSTREAM chunks are read and the reply is FOUND when the stream holds the EICAR
// string, or an ERROR once more than limit bytes arrive. It listens on a unix socket, or on loopback TCP through Dial
// where unix sockets are missing, so the clamd tests never pass by skipping.
func fakeClamd(t *testing.T, limit int) Clamd {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clamd.sock")
	c := Clamd{Socket: path}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		ln = listenTCP(t)
		c = Clamd{Dial: dialTo(ln.Addr())}
	}
	serveOn(t, ln, limit)
	return c
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func dialTo(addr net.Addr) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, addr.Network(), addr.String())
	}
}

func serveOn(t *testing.T, ln net.Listener, limit int) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveClamd(conn, limit)
		}
	}()
}

func serveClamd(conn net.Conn, limit int) {
	defer func() { _ = conn.Close() }()
	var cmd []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, one); err != nil {
			return
		}
		if one[0] == 0 {
			break
		}
		cmd = append(cmd, one[0])
	}
	if string(cmd) == "zVERSION" {
		_, _ = conn.Write([]byte("ClamAV 1.0.1/27000/Mon\x00"))
		return
	}
	var got []byte
	for {
		var size [4]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(size[:])
		if n == 0 {
			break
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(conn, chunk); err != nil {
			return
		}
		got = append(got, chunk...)
		if limit > 0 && len(got) > limit {
			_, _ = conn.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
			// Closing with unread input resets the connection on Windows and drops the reply.
			_, _ = io.Copy(io.Discard, conn)
			return
		}
	}
	if strings.Contains(string(got), eicar()) {
		_, _ = conn.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
		return
	}
	_, _ = conn.Write([]byte("stream: OK\x00"))
}

func silentDaemon(context.Context) (net.Conn, error) {
	c, _ := net.Pipe()
	return c, nil
}

// A Read of 0, nil is legal and must not send INSTREAM's end-of-stream chunk.
type delayedReader struct {
	once bool
	io.Reader
}

func (d *delayedReader) Read(p []byte) (int, error) {
	if !d.once {
		d.once = true
		return 0, nil
	}
	return d.Reader.Read(p)
}

func TestClamdProtocolFlagsOnlyTheInfectedFile(t *testing.T) {
	t.Parallel()
	dir := writeTree(t, map[string]string{"a/clean.dll": "hello", "b/bad.dll": "prefix" + eicar()})
	got, found, err := fakeClamd(t, 0).Scan(t.Context(), dir)
	if err != nil || !found || got.Name != "Eicar-Test-Signature" || got.File != "b/bad.dll" || got.Scanner != "clamd" {
		t.Fatalf("detection = %+v, err = %v", got, err)
	}
	clean := writeTree(t, map[string]string{"a.dll": "fine"})
	if got, found, err := fakeClamd(t, 0).Scan(t.Context(), clean); found || err != nil {
		t.Fatalf("clean tree = %+v, %v", got, err)
	}
	if got, found, err := fakeClamd(t, 0).ScanReader(t.Context(), "bad.dll", &delayedReader{Reader: strings.NewReader(eicar())}); err != nil || !found || got.Name != "Eicar-Test-Signature" {
		t.Fatalf("a 0-byte Read ended the stream: %+v, %v, %v", got, found, err)
	}
}

func TestClamdStreamLimitIsAFailedScan(t *testing.T) {
	t.Parallel()
	dir := writeTree(t, map[string]string{"big.bin": strings.Repeat("x", 200_000), "bad.dll": eicar()})
	if got, found, err := fakeClamd(t, 100_000).Scan(t.Context(), dir); !found || got.File != "bad.dll" || err != nil {
		t.Fatalf("a detection after the big file: %+v, %v", got, err)
	}
	dir = writeTree(t, map[string]string{"big.bin": strings.Repeat("x", 200_000)})
	_, found, err := fakeClamd(t, 100_000).Scan(t.Context(), dir)
	if found || !errors.Is(err, ErrTooLarge) || err.Error() != "big.bin: "+ErrTooLarge.Error() {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestClamdNotRegularAtOpenIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("opening a directory as a file is Unix")
	}
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	_, err = (Clamd{}).scanFile(t.Context(), root, "sub")
	if !errors.Is(err, errNotRegular) {
		t.Fatalf("err = %v, want errNotRegular", err)
	}
}

func TestClamdEmptyDirNeedsADaemon(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing := Clamd{Socket: filepath.Join(t.TempDir(), "none.sock")}
	if _, found, err := missing.Scan(t.Context(), dir); found || !errors.Is(err, ErrNoScanner) {
		t.Fatalf("missing daemon on empty dir: found=%v err=%v", found, err)
	}
	if d, found, err := fakeClamd(t, 0).Scan(t.Context(), dir); found || err != nil {
		t.Fatalf("fake daemon on empty dir = %+v, %v, %v", d, found, err)
	}
	// A listener that accepts and never answers is not a daemon.
	ln := listenTCP(t)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	silent := Clamd{Dial: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, found, err := silent.Scan(ctx, dir); found || err == nil {
		t.Fatalf("silent listener on empty dir: found=%v err=%v", found, err)
	}
}

func TestClamdWithoutADaemonIsNoScanner(t *testing.T) {
	t.Parallel()
	dir := writeTree(t, map[string]string{"a.dll": "x"})
	c := Clamd{Socket: filepath.Join(t.TempDir(), "none.sock")}
	if _, _, err := c.Scan(t.Context(), dir); !errors.Is(err, ErrNoScanner) {
		t.Fatalf("err = %v", err)
	}
	failing := Clamd{Dial: func(context.Context) (net.Conn, error) { return nil, errors.New("refused") }}
	if _, err := failing.Version(t.Context()); !errors.Is(err, ErrNoScanner) {
		t.Fatalf("a Dial error is no daemon, got %v", err)
	}
}

func TestClamdDialReachesADaemonOverAnyTransport(t *testing.T) {
	t.Parallel()
	ln := listenTCP(t)
	serveOn(t, ln, 0)
	c := Clamd{Dial: dialTo(ln.Addr())}
	got, err := c.Version(t.Context())
	if err != nil || got != "ClamAV 1.0.1/27000/Mon" {
		t.Fatalf("version = %q, %v", got, err)
	}
	dir := writeTree(t, map[string]string{"bad.dll": eicar()})
	if d, found, err := c.Scan(t.Context(), dir); !found || err != nil || d.File != "bad.dll" {
		t.Fatalf("scan over TCP = %+v, %v, %v", d, found, err)
	}
	partial, full := net.Pipe()
	go func() {
		_, _ = io.ReadFull(full, make([]byte, len("zVERSION\x00")))
		_, _ = full.Write([]byte("ClamAV 1.0.1"))
		_ = full.Close()
	}()
	if got, err := (Clamd{Dial: func(context.Context) (net.Conn, error) { return partial, nil }}).Version(t.Context()); err != nil || got != "ClamAV 1.0.1" {
		t.Fatalf("unterminated version = %q, %v", got, err)
	}
	emptyC, emptyS := net.Pipe()
	go func() {
		_, _ = io.ReadFull(emptyS, make([]byte, len("zVERSION\x00")))
		_ = emptyS.Close()
	}()
	if _, err := (Clamd{Dial: func(context.Context) (net.Conn, error) { return emptyC, nil }}).Version(t.Context()); err == nil {
		t.Fatal("an empty version was accepted")
	}
}

// Callers persist Detection, so its JSON keys are part of the contract.
func TestDetectionJSONKeys(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(Detection{Name: "n", File: "f", Scanner: "s"})
	if err != nil || string(b) != `{"name":"n","file":"f","scanner":"s"}` {
		t.Fatalf("json = %s, %v", b, err)
	}
}

func TestSplitCommandKeepsQuotedParts(t *testing.T) {
	t.Parallel()
	got := splitCommand(`"C:\Program Files\av\scan.exe" --quiet "{path}"`)
	if len(got) != 3 || got[0] != `C:\Program Files\av\scan.exe` || got[2] != "{path}" {
		t.Fatalf("parts = %q", got)
	}
}

func TestCommandProgramIsTheFirstPartsBaseName(t *testing.T) {
	t.Parallel()
	if got := (Command{Line: `"/opt/av dir/scan" {path}`}).Program(); got != "scan" {
		t.Fatalf("program = %q", got)
	}
	if got := (Command{}).Program(); got != "" {
		t.Fatalf("empty program = %q", got)
	}
}

func TestCustomCommandExitCodeDecidesAndStdoutNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	t.Parallel()
	dir := writeTree(t, map[string]string{"a.dll": "x"})
	if got, found, err := (Command{Line: `sh -c "test -d {path}"`}).Scan(t.Context(), dir); found || err != nil {
		t.Fatalf("clean = %+v, %v", got, err)
	}
	got, found, err := Command{Line: `sh -c "echo Win.Test.Bad; exit 1" {path}`}.Scan(t.Context(), dir)
	if err != nil || !found || got.Name != "Win.Test.Bad" || got.Scanner != "sh" {
		t.Fatalf("detection = %+v, %v", got, err)
	}
	got, found, err = Command{Line: `sh -c "exit 1" {path}`}.Scan(t.Context(), dir)
	if err != nil || !found || got.Name != "" || got.Scanner != "sh" {
		t.Fatalf("a silent detection has no name: %+v, %v", got, err)
	}
	if _, _, err := (Command{Line: "no-such-scanner-xyz {path}"}).Scan(t.Context(), dir); err == nil || errors.Is(err, ErrNoScanner) {
		t.Fatalf("a missing program is an error, got %v", err)
	}
	if _, _, err := (Command{}).Scan(t.Context(), dir); !errors.Is(err, ErrNoScanner) {
		t.Fatalf("empty command err = %v", err)
	}
}

func TestCommandKilledBySignalIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses SIGSEGV")
	}
	t.Parallel()
	dir := writeTree(t, map[string]string{"a.dll": "x"})
	got, found, err := (Command{Line: `sh -c "kill -s SEGV $$" {path}`}).Scan(t.Context(), dir)
	if found || err == nil {
		t.Fatalf("signal death counted as detection: %+v found=%v err=%v", got, found, err)
	}
}

func TestACancelledContextStopsEveryScanner(t *testing.T) {
	t.Parallel()
	dir := writeTree(t, map[string]string{"a.dll": "x", "b.dll": "y"})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	scanners := map[string]Scanner{"clamd": Clamd{Dial: silentDaemon}}
	if runtime.GOOS != "windows" {
		scanners["command"] = Command{Line: "sleep 30 {path}"}
	}
	for name, sc := range scanners {
		if _, found, err := sc.Scan(ctx, dir); found || !errors.Is(err, context.Canceled) {
			t.Errorf("%s: found=%v err=%v, want context.Canceled", name, found, err)
		}
	}
}

// A daemon that accepts and never answers must not hold a caller past its own deadline.
func TestClamdVersionKeepsTheCallersDeadline(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (Clamd{Dial: silentDaemon}).Version(ctx); err == nil {
		t.Fatal("a silent daemon answered")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("Version took %v past a 200 ms deadline", took)
	}
}

// A scanner whose child keeps stdout open must not outlive cancellation by the child's lifetime.
func TestCustomCommandStopsWhenAChildKeepsItsOutputOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	t.Parallel()
	dir := writeTree(t, map[string]string{"a.dll": "x"})
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, found, err := (Command{Line: `sh -c "sleep 30 & sleep 30" {path}`}).Scan(ctx, dir); found || err == nil {
		t.Fatalf("found=%v err=%v, want an error", found, err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("Scan took %v after a 200 ms deadline", took)
	}
}

func TestSecurityCenterProductsNamesOrErrors(t *testing.T) {
	t.Parallel()
	names, err := SecurityCenterProducts(t.Context())
	if runtime.GOOS != "windows" {
		if !errors.Is(err, ErrNoScanner) {
			t.Fatalf("off Windows err = %v", err)
		}
		return
	}
	// A hosted Windows Server has no SecurityCenter2 namespace, so an error is as valid as a list.
	if err == nil && len(names) == 0 {
		t.Fatal("no error and no names")
	}
}

// A write that fails because clamd closed early is explained by whatever clamd said before closing; with nothing said,
// the write error stands.
func TestParseReplyUnterminatedOKIsAnError(t *testing.T) {
	t.Parallel()
	name, err := parseReply(strings.NewReader("stream: OK"))
	if name != "" || err == nil {
		t.Fatalf("unterminated OK = %q, %v; want error", name, err)
	}
}

func TestParseReplyEmptyFoundNameIsAnError(t *testing.T) {
	t.Parallel()
	for _, reply := range []string{"stream: FOUND\x00", "stream: \x01\x02 FOUND\x00"} {
		name, err := parseReply(strings.NewReader(reply))
		if name != "" || err == nil {
			t.Fatalf("reply %q = %q, %v; want error", reply, name, err)
		}
	}
}

func TestReplyOnWriteError(t *testing.T) {
	t.Parallel()
	if name, err := parseReply(strings.NewReader("stream: Eicar-Test-Signature FOUND")); name != "Eicar-Test-Signature" || err != nil {
		t.Fatalf("unterminated FOUND = %q, %v", name, err)
	}
	if name, err := parseReply(strings.NewReader("")); name != "" || !errors.Is(err, io.EOF) {
		t.Fatalf("silence = %q, %v", name, err)
	}
	writeErr := errors.New("broken pipe")
	for name, c := range map[string]struct{ reply, wantName string }{
		"clamd named a threat": {"stream: Eicar-Test-Signature FOUND\x00", "Eicar-Test-Signature"},
		"clamd said nothing":   {"", ""},
		"clamd said OK":        {"stream: OK\x00", ""},
	} {
		client, server := net.Pipe()
		go func() {
			_, _ = server.Write([]byte(c.reply))
			_ = server.Close()
		}()
		name2, err := replyOnWriteError(client, writeErr)
		_ = client.Close()
		if name2 != c.wantName || (c.wantName == "" && !errors.Is(err, writeErr)) || (c.wantName != "" && err != nil) {
			t.Errorf("%s: %q, %v", name, name2, err)
		}
	}
	endC, endS := net.Pipe()
	go func() {
		one := make([]byte, 1)
		for {
			if _, err := io.ReadFull(endS, one); err != nil || one[0] == 0 {
				_ = endS.Close()
				return
			}
		}
	}()
	_, _, err := (Clamd{Dial: func(context.Context) (net.Conn, error) { return endC, nil }}).ScanReader(t.Context(), "f", strings.NewReader(""))
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("terminator write err = %v", err)
	}
}
