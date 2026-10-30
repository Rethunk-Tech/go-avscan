package avscan

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"time"
)

// defaultSockets are where distributions put clamd's socket.
var defaultSockets = []string{
	"/run/clamav/clamd.ctl",
	"/var/run/clamav/clamd.ctl",
	"/run/clamd.scan/clamd.sock",
	"/var/run/clamd.scan/clamd.sock",
	"/tmp/clamd.socket",
}

const (
	clamdChunk   = 64 * 1024
	clamdTimeout = 30 * time.Second
)

// ErrTooLarge is a file over clamd's StreamMaxLength. It is a failed scan, never a clean one, and is wrapped with the
// file's slash path.
var ErrTooLarge = errors.New("too large for the antivirus to scan")

// Clamd streams each file to a clamd daemon (INSTREAM), so the daemon needs no read access to the scanned folder.
type Clamd struct {
	// Socket is clamd's unix socket, trusted as given. "" tries the distribution default sockets, skipping any not
	// owned by root or the clamav user, so another local user who binds a world-writable path cannot answer "OK".
	Socket string
	// Dial opens a connection to clamd, for a daemon on TCP or TLS. When set it replaces Socket and the default list,
	// and the caller owns trusting what it dials. An error from Dial counts as no daemon.
	Dial func(ctx context.Context) (net.Conn, error)
}

func (c Clamd) candidates() []string {
	if c.Socket != "" {
		return []string{c.Socket}
	}
	var out []string
	for _, p := range defaultSockets {
		if trustedSocketOwner(p) {
			out = append(out, p)
		}
	}
	return out
}

func (c Clamd) connect(ctx context.Context) (net.Conn, error) {
	if c.Dial != nil {
		conn, err := c.Dial(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNoScanner, err)
		}
		return conn, nil
	}
	d := &net.Dialer{Timeout: clamdTimeout}
	for _, path := range c.candidates() {
		if conn, err := d.DialContext(ctx, "unix", path); err == nil {
			return conn, nil
		}
	}
	return nil, ErrNoScanner
}

// Scan streams every file under dir and returns the first detection. A file over clamd's size limit does not stop the
// walk, so a later detection still wins; with none, the first such file is reported as [ErrTooLarge]. With no
// reachable daemon the error is [ErrNoScanner].
func (c Clamd) Scan(ctx context.Context, dir string) (Detection, bool, error) {
	var found Detection
	var hit bool
	errStop := errors.New("stop")
	var tooLarge error
	err := files(ctx, dir, func(root *os.Root, rel string) error {
		name, err := c.scanFile(ctx, root, rel)
		if errors.Is(err, ErrTooLarge) {
			tooLarge = cmp.Or(tooLarge, fmt.Errorf("%s: %w", rel, err))
			return nil
		}
		if err != nil {
			return err
		}
		if name != "" {
			found, hit = Detection{Name: name, File: rel, Scanner: "clamd"}, true
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return Detection{}, false, err
	}
	if !hit && tooLarge != nil {
		return Detection{}, false, tooLarge
	}
	return found, hit, nil
}

// scanFile returns the threat clamd names for the file, or "" when it is clean; ErrTooLarge when the file is over
// clamd's stream limit.
func (c Clamd) scanFile(ctx context.Context, root *os.Root, rel string) (string, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	stop := bound(ctx, conn)
	defer stop()
	in, err := root.Open(rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", err
	}
	buf := make([]byte, clamdChunk)
	size := make([]byte, 4)
	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			if n > math.MaxUint32 {
				return "", errors.New("chunk too large")
			}
			binary.BigEndian.PutUint32(size, uint32(n))
			if _, err := conn.Write(size); err != nil {
				return replyOnWriteError(conn, err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return replyOnWriteError(conn, err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return replyOnWriteError(conn, err)
	}
	return parseReply(conn)
}

// replyOnWriteError reads what clamd said when it closed the stream early (its size limit), else reports the write
// error.
func replyOnWriteError(conn net.Conn, writeErr error) (string, error) {
	name, err := parseReply(conn)
	if err == nil || errors.Is(err, ErrTooLarge) {
		return name, err
	}
	return "", writeErr
}

// parseReply reads one NUL-terminated answer: "stream: OK", "stream: <name> FOUND" or "<message> ERROR".
func parseReply(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, 4096)).ReadString(0)
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimSpace(strings.TrimRight(line, "\x00"))
	switch {
	case strings.HasSuffix(line, " FOUND"):
		name := strings.TrimSuffix(line, " FOUND")
		return strings.TrimSpace(strings.TrimPrefix(name, "stream:")), nil
	case strings.HasSuffix(line, "size limit exceeded. ERROR"):
		return "", ErrTooLarge
	case strings.HasSuffix(line, " OK"):
		return "", nil
	}
	return "", fmt.Errorf("clamd answered %q", line)
}

// Version asks clamd for its version line ("ClamAV 1.0.1/..."), reporting [ErrNoScanner] when no daemon answers.
func (c Clamd) Version(ctx context.Context) (string, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	stop := bound(ctx, conn)
	defer stop()
	if _, err := conn.Write([]byte("zVERSION\x00")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString(0)
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(strings.TrimRight(line, "\x00")), nil
}

// bound gives conn clamdTimeout, or ctx's deadline when that is sooner, and ends a blocked read or write as soon as
// ctx is cancelled rather than at the deadline. The returned func releases the cancellation hook.
func bound(ctx context.Context, conn net.Conn) func() bool {
	deadline := time.Now().Add(clamdTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	return context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
}
