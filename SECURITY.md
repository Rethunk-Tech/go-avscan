# Security

## Supported versions

The latest tagged release. There are no long-lived release branches, so a fix ships in the next tag
rather than being backported.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security → Report a
vulnerability). It stays private until a fix ships.

Please do not open a public issue for a suspected vulnerability first.

## What is in scope

- A scanned folder's contents, which may be hostile: a symlink or crafted path must not lead `Clamd.Scan`, `AMSI.Scan` or `Command` to read a file outside the folder (the walk and every open go through one `os.Root`).
- A clamd reply: `parseReply` reads at most 4 KiB and must not panic or report a file clean on an unrecognised answer; it is an error.
- A file of any size: it is streamed in fixed chunks, never loaded whole by clamd scans, and a file over clamd's limit must be a failed scan, not a clean one.
- A default-list clamd socket: another local user must not be able to stand in for the daemon, so such a socket counts only when owned by root or `clamav`.

## What is out of scope

- The `Command` line, the `Clamd.Socket` and what `Clamd.Dial` connects to come from the caller, who is trusted to choose them; `Command` runs the program with the caller's privileges and no shell.
- A scanner that is wrong, unreachable or evaded is outside the module: a clean result is the antivirus's word, not a proof.
- A file changed after it was scanned is the caller's to prevent.
