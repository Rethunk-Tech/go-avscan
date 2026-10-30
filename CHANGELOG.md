# Changelog

Notable changes to `go-avscan`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Scanner`, `Detection`, `ErrNoScanner`: the interface every scanner implements and the result it returns. Every scan walks the folder through one `os.Root`, so a symlink cannot lead it outside.
- `Clamd`: scans a folder through a clamd daemon over INSTREAM, on a unix socket or any connection `Dial` returns, with `Version` for health checks. A file over clamd's size limit is `ErrTooLarge`, never clean.
- `Command`: scans a folder with a program the caller names, no shell, and `Program` for its name.
- `AMSI`: scans a folder through the Windows AMSI provider; `SecurityCenterProducts` lists the antivirus products Windows Security Center registers.

[Unreleased]: https://github.com/Rethunk-Tech/go-avscan/commits/main
