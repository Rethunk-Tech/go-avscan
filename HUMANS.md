# HUMANS.md

Run and use `go-avscan`. Internals: [AGENTS.md](AGENTS.md).

## Quick start

```bash
go get github.com/Rethunk-Tech/go-avscan
```

```go
package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Rethunk-Tech/go-avscan"
)

// check reports whether dir is safe to use; a machine with no scanner counts as safe here, a choice the caller makes.
func check(ctx context.Context, s avscan.Scanner, dir string) error {
	d, found, err := s.Scan(ctx, dir)
	switch {
	case errors.Is(err, avscan.ErrNoScanner):
		return nil
	case err != nil:
		return err
	case found:
		return fmt.Errorf("%s flagged %q: %s", d.Scanner, d.File, d.Name)
	}
	return nil
}

func main() {
	var s avscan.Scanner = avscan.Clamd{}
	_ = check
	fmt.Printf("%T\n", s)
	fmt.Println(avscan.Command{Line: `clamdscan --no-summary "{path}"`}.Program())
}
```

## Contracts

| Behaviour | Contract |
| --- | --- |
| `Scanner.Scan` | Walks `dir` once and visits regular files only; symlinks, devices and pipes are skipped. `found` reports a detection; an error is a scan that did not finish and says nothing about the files |
| `Detection.File` | Relative to `dir`, slash-separated on every OS; `""` when the scanner does not say which file |
| `Detection.Name` | The scanner's threat name; `""` when it names none (AMSI never does, and a silent command does not) |
| `Detection.Scanner` | `"clamd"`, `"AMSI"`, or the base name of the command's program |
| `ErrNoScanner` | No AMSI provider, no reachable clamd, an empty command line, or AMSI off Windows. Test with `errors.Is` |
| `ErrTooLarge` | clamd refused a file over its size limit; wrapped with the file's path. A later detection in the same folder still wins; with none, this is the error |
| `Clamd.Socket` | Trusted as given. `""` tries the distribution's default sockets, skipping any not owned by root or the `clamav` user on Unix |
| `Clamd.Dial` | Replaces `Socket` and the default list; the caller owns trusting what it dials. A dial error is `ErrNoScanner` |
| `Clamd.Version` | The daemon's version line; `ErrNoScanner` when none answers |
| `Command` | No shell. Double quotes keep a part whole; `{path}` in any part becomes `dir`. Exit 0 is clean, any other exit code is a detection named by the first non-empty output line. A program that does not start is an error |
| `AMSI` | `AppName` is registered with `AmsiInitialize`; `""` uses the executable's base name. A file Windows refuses as infected is a detection |
| `SecurityCenterProducts` | Display names, one per product. An unreadable Security Center is an error and an empty one is `ErrNoScanner` |
| Context | Cancellation or a deadline ends a blocked read, write or child process; a clamd connection also ends after a fixed time |

## Requirements

Go 1.27.3 or newer, plus `lefthook` and `gitleaks` on PATH if you want the git hooks.

```bash
lefthook install
```

That is per clone; git does not commit hooks. Pre-commit scans staged changes for secrets, and
pre-push runs `gate`.

## Verify

```bash
gate
```
