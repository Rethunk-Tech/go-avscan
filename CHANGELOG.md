# Changelog

Notable changes to `go-avscan`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Rethunk-Tech/go-avscan/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/Rethunk-Tech/go-avscan/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Rethunk-Tech/go-avscan/compare/v0.2.0...v0.2.1
[0.1.0]: https://github.com/Rethunk-Tech/go-avscan/releases/tag/v0.1.0
