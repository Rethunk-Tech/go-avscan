# Changelog

Notable changes to `go-avscan`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cmd/avscan` scans a directory through clamd, a named command, or Windows AMSI.

### Fixed

- `avscan -command` now refuses a command line that does not contain `{path}`, so a scanner is never invoked without
  the directory it is meant to scan.
- `avscan` resolves DIR to an absolute path before scanning, so a folder named `--version` reaches the scanner as a
  path instead of a flag.
- A clamd scan of an empty or symlink-only folder now fails with `ErrNoScanner` when no daemon answers, instead of
  reporting the folder clean.
- A command scanner killed by a signal is an error, not a detection.
- A file swapped for a directory or FIFO after the walk is an error, not a skipped (clean) path.
- A clamd `FOUND` reply with no threat name is an error, not a clean scan.
- An unterminated clamd `OK` reply is an error, not a clean scan.
- A clamd scan whose write failed partway no longer counts an `OK` reply as clean: only a detection or the size-limit
  error overrides the write error, since clamd never saw the rest of the file.

## [0.3.0] - 2026-11-10

### Changed

- The module path is now `github.com/Totative/go-avscan`; update imports and the `require` line in `go.mod`.
- The licence is now Apache-2.0.

### Added

- Each release tarball carries a signed build provenance and an SBOM attestation; check one with `gh attestation verify <file> --owner Totative`.

## [0.2.2] - 2026-11-07

### Fixed

- The same code as 0.2.1, released again: 0.2.1's tag moved after the Go module proxy had cached it, so `go get` from the proxy and from GitHub disagreed on its checksum. Use 0.2.2.

## [0.2.1] - 2026-11-07

### Fixed

- A default-list clamd socket that cannot be stat'ed is no longer trusted, and on Linux the connection's peer uid must be root or `clamav`, so a socket another user binds in `/tmp` cannot answer "OK".
- AMSI results `0x4000`-`0x4FFF` (blocked by administrator policy) are detections instead of clean; AMSI chunks overlap by 1 MiB and a small file allocates only its own size.
- A file swapped for a FIFO after the walk is skipped instead of blocking the scan.
- `Command` keeps at most 64 KiB of output, and threat names are stripped of control characters and cut to 256 bytes.
- A cancelled context during `Clamd.Dial` returns the context's error, not `ErrNoScanner`.

## [0.2.0] - 2026-11-03

### Added

- `Clamd.ScanReader`: scans one stream, for a server screening an upload without writing it to a folder first.

## [0.1.0] - 2026-10-29

### Added

- `Scanner`, `Detection`, `ErrNoScanner`: the interface every scanner implements and the result it returns. Every scan walks the folder through one `os.Root`, so a symlink cannot lead it outside.
- `Clamd`: scans a folder through a clamd daemon over INSTREAM, on a unix socket or any connection `Dial` returns, with `Version` for health checks. A file over clamd's size limit is `ErrTooLarge`, never clean.
- `Command`: scans a folder with a program the caller names, no shell, and `Program` for its name.
- `AMSI`: scans a folder through the Windows AMSI provider; `SecurityCenterProducts` lists the antivirus products Windows Security Center registers.

[Unreleased]: https://github.com/Totative/go-avscan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Totative/go-avscan/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Totative/go-avscan/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Totative/go-avscan/compare/v0.2.0...v0.2.1
[0.1.0]: https://github.com/Totative/go-avscan/releases/tag/v0.1.0
