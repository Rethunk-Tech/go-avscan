package avscan

import (
	"context"
	"errors"
	"io/fs"
	"os"
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
