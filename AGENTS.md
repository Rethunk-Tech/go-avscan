# AGENTS.md

Package `avscan` asks the machine's antivirus about a folder of files: Windows AMSI, a clamd daemon, or a command the caller names. Programs that take files from elsewhere and want a second opinion import it. It knows nothing of its callers' settings, stores or wording, and imports no consumer package.

## Gate

`gate` is the command. Each override in `.gate.toml` is there because a runner
cannot resolve that check from PATH.

No test here proves an AMSI detection on CI: a hosted Windows runner has Defender's real-time protection off, so `TestAMSIFlagsTheMicrosoftTestSample` skips when the sample comes back clean and real-time is off, and the job proves only that a session opens and a clean folder reads clean. The AMSI and `SecurityCenterProducts` tests run only in the `windows-latest` job; the clamd and command tests run on both legs, and the `sh`-based command tests skip on Windows.

## Shape

- `files` is the only walk. It opens the folder once as an `os.Root` and hands each scanner the root plus a slash path, so no component under the folder can escape it. A scanner never joins paths itself.
- The scanners are the exported structs `Clamd`, `Command` and `AMSI`; there is no constructor, mode string or settings mapping, because choosing a scanner is the caller's policy.
- `defaultSockets` stays unexported: tests replace it, and a caller who wants another socket sets `Socket` or `Dial`.
- A default-list socket must be owned by root or `clamav`, since the list includes world-writable `/tmp` and another user could answer "OK" to everything. A configured `Socket` is trusted as given, and `Dial` bypasses the list.
- A clamd write error first reads the reply (`replyOnWriteError`): clamd closes the stream when a file exceeds its limit, and that reply, not the broken pipe, is the answer.
- `bound` gives each connection a fixed timeout or the caller's sooner deadline, and cancels a blocked read or write on context cancellation; without it a silent daemon holds the caller.
- `Command` sets `WaitDelay` because a killed scanner can leave a child holding its output open.
- Threat names are never invented: AMSI and a silent command return `Name: ""`, and wording is the caller's.
- `Detection` keeps its JSON tags; callers persist it.

## Files

| File | Holds |
| --- | --- |
| `doc.go` | Package doc |
| `avscan.go` | `ErrNoScanner`, `Detection`, `Scanner`, and the `os.Root` walk |
| `clamd.go` | `Clamd`, `ErrTooLarge`, INSTREAM, reply parsing, connection bounds |
| `command.go` | `Command`, command-line splitting |
| `owner_unix.go`, `owner_other.go` | Default-socket owner check (root or `clamav`; always true off Unix) |
| `amsi_windows.go`, `amsi_other.go` | `AMSI` through `amsi.dll`; the stub that returns `ErrNoScanner` |
| `product_windows.go`, `product_other.go` | `SecurityCenterProducts` through PowerShell; the stub |
