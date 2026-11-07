package avscan

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"unicode"
)

// ErrNoScanner means the scanner is not there: no AMSI provider, no reachable clamd, an empty command line. It is not
// a failure to report, since most Linux machines run no daemon; a caller that wants "no scanner" to mean "skip" tests
// for it.
var ErrNoScanner = errors.New("no antivirus scanner available")

// Detection is what a scanner flagged: its name for the threat ("" when the scanner does not name one), the file
// relative to the scanned folder in slash form ("" when the scanner does not say), and which scanner flagged it:
// "clamd", "AMSI", or the base name of a [Command]'s program.
type Detection struct {
	Name    string `json:"name"`
	File    string `json:"file"`
	Scanner string `json:"scanner"`
}

// Scanner scans a folder. The bool reports a detection; an error is a scan that did not finish and says nothing about
// the files.
type Scanner interface {
	Scan(ctx context.Context, dir string) (d Detection, found bool, err error)
}

// files calls visit for each regular file under dir with the folder's root and the file's slash path inside it,
// stopping at the first error or when the context ends. Symlinks, devices and pipes are skipped, and visit opens files
// through the root, so nothing under dir can lead the scan outside it.
func files(ctx context.Context, dir string, visit func(root *os.Root, rel string) error) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return visit(root, rel)
	})
}

// errNotRegular is a path that was a regular file when the walk saw it and is not any more.
var errNotRegular = errors.New("not a regular file")

// openRegular opens rel for reading without waiting on it, and fails with errNotRegular when it is not a regular
// file: a file swapped for a FIFO after the walk saw it would otherwise block the open until something writes to it.
func openRegular(root *os.Root, rel string) (*os.File, error) {
	f, err := root.OpenFile(rel, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, errNotRegular
	}
	return f, nil
}

// maxNameLen bounds a threat name taken from a scanner's output, which can echo text the scanned files control.
const maxNameLen = 256

// cleanName trims a threat name, drops control characters and cuts it to maxNameLen bytes on a rune boundary.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > maxNameLen {
		s = strings.ToValidUTF8(s[:maxNameLen], "")
	}
	return s
}
