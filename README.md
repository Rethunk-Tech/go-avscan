<h1 align="center">go-avscan</h1>

<div align="center">

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.27.3+-00ADD8?logo=go&logoColor=white)](go.mod)

</div>

---

Asks the machine's antivirus about a folder of files: Windows AMSI, a clamd daemon, or a command you name. Package `avscan`, module `github.com/Totative/go-avscan`.

Every scanner answers the same question for a folder: did the antivirus flag anything, and which file. A scan that could not run says so with an error and never reads as a clean result, and a machine with no scanner is a distinct, checkable error (`ErrNoScanner`) so a caller can choose to skip.

## Quick start

```bash
go get github.com/Totative/go-avscan
```

A worked example and the contracts: [HUMANS.md](HUMANS.md).

## Features

- One `Scanner` interface for every backend.
- Files are opened through the scanned folder's root, so a symlink cannot lead a scan outside it.
- A file clamd refuses for size is a failed scan (`ErrTooLarge`), never a clean one.
- Every network and process wait ends with the caller's context.
- clamd on a unix socket or any connection you dial (TCP, TLS), with a version query.
- Lists the antivirus products Windows Security Center knows.

## Command-line tool

```bash
go install github.com/Totative/go-avscan/cmd/avscan@latest
```

`avscan [flags] DIR` scans one directory. Choose exactly one of `-clamd ADDR` (`unix:/path` or `tcp:host:port`), `-command LINE`, or `-amsi` (Windows AMSI).

Exit 0 is clean, 1 a detection, and 2 any error (usage, timeout, or a scan that did not finish).

```json
{"dir":"/inbox","scanner":"command","clean":true,"detection":null,"error":null}
```

## Documentation

| Doc | Audience |
| --- | --- |
| [HUMANS.md](HUMANS.md) | Running and using the package |
| [AGENTS.md](AGENTS.md) | Internals, invariants, and why |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Process — commits, tests, docs |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## License

Apache-2.0, see [LICENSE](LICENSE). © 2026 Damon Blais.
