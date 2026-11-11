package avscan

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Rethunk-Tech/go-desktopenv/nowindow"
)

// Command runs a scanner program the caller names. Line is split on spaces and tabs with no shell; a double-quoted
// part stays whole, and "{path}" in any part is replaced by the folder. Exit 0 is clean; any other exit code is a
// detection whose name is the first non-empty line of the program's output ("" when it prints none). A program that
// does not start is an error, an empty Line is [ErrNoScanner], and a Line without "{path}" is refused, since the
// program would never be given the folder.
type Command struct{ Line string }

// splitCommand splits a command line on spaces, keeping a double-quoted part whole.
func splitCommand(line string) []string {
	var out []string
	var cur strings.Builder
	quoted, started := false, false
	for _, r := range line {
		switch {
		case r == '"':
			quoted, started = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// Program is the base name of the command's first part, "" when Line is empty.
func (c Command) Program() string {
	parts := splitCommand(c.Line)
	if len(parts) == 0 {
		return ""
	}
	return filepath.Base(parts[0])
}

// errNoPathInLine refuses a command line that would never be given the folder.
var errNoPathInLine = errors.New("avscan: command line has no {path}")

// commandWaitDelay is how long a cancelled scan waits for the scanner's leftover children to close its output.
const commandWaitDelay = 2 * time.Second

// Scan runs the command once for the whole folder; File of a detection is "" because a command does not say which
// file it flagged.
func (c Command) Scan(ctx context.Context, dir string) (Detection, bool, error) {
	parts := splitCommand(c.Line)
	if len(parts) == 0 {
		return Detection{}, false, ErrNoScanner
	}
	// Without {path} the program never learns which folder to scan, and its exit 0 would read as this folder clean.
	if !strings.Contains(c.Line, "{path}") {
		return Detection{}, false, errNoPathInLine
	}
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(p, "{path}", dir)
	}
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...) //nolint:gosec // G204: argv is the caller's configured scanner command with {path} substituted
	nowindow.Set(cmd)
	// A scanner can leave a child holding stdout open after it is killed; WaitDelay ends the wait for it.
	cmd.WaitDelay = commandWaitDelay
	var out cappedBuffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err == nil {
		return Detection{}, false, nil
	}
	if ctx.Err() != nil {
		return Detection{}, false, ctx.Err()
	}
	if ee, exited := errors.AsType[*exec.ExitError](err); exited {
		if ee.ExitCode() == -1 {
			return Detection{}, false, fmt.Errorf("run %s: %w", parts[0], err)
		}
		return Detection{Name: firstLine(out.String()), Scanner: filepath.Base(parts[0])}, true, nil
	}
	return Detection{}, false, fmt.Errorf("run %s: %w", parts[0], err)
}

func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return cleanName(line)
		}
	}
	return ""
}

// commandOutputCap is how much of a scanner's output is kept: the name comes from its first line, and a scanner that
// prints without end must not fill memory.
const commandOutputCap = 64 << 10

// cappedBuffer keeps the first commandOutputCap bytes written and discards the rest, still reporting every write as
// taken so the program is not blocked on a full pipe.
type cappedBuffer struct{ b []byte }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := commandOutputCap - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return string(c.b) }
