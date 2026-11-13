//go:build unix

package avscan

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// trustedSocketOwner reports whether a default-list socket is owned by root or a system account, so another local
// user who binds a world-writable path (/tmp) cannot answer "OK" for every scan. A path that cannot be stat'ed is
// not trusted: a socket another user binds after the check must not pass for one that was never seen.
func trustedSocketOwner(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && trustedUID(st.Uid)
}

// trustedUID accepts root and any system account (below UID_MIN), whatever the distribution names its clamd user
// (clamav, clamscan, clamd). The current user is never trusted unless root: a socket this user can bind proves nothing.
func trustedUID(uid uint32) bool {
	if uid == 0 {
		return true
	}
	return uid < systemUIDLimit() && int64(uid) != int64(os.Geteuid())
}

func uidMinFallback(goos string) uint32 {
	// macOS has no login.defs and regular users start at 501, so the Linux 1000
	// fallback would treat a neighbour's /tmp clamd as a system daemon.
	if goos == "darwin" {
		return 500
	}
	return 1000
}

func systemUIDLimit() uint32 {
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return uidMinFallback(runtime.GOOS)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "UID_MIN" {
			if v, err := strconv.ParseUint(f[1], 10, 32); err == nil {
				return uint32(v)
			}
		}
	}
	return uidMinFallback(runtime.GOOS)
}
