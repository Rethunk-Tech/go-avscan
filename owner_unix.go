//go:build unix

package avscan

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// trustedSocketOwner reports whether a default-list socket is owned by root or the clamav user, so another local
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

func trustedUID(uid uint32) bool {
	if uid == 0 {
		return true
	}
	u, err := user.Lookup("clamav")
	if err != nil {
		return false
	}
	clamav, err := strconv.ParseUint(u.Uid, 10, 32)
	return err == nil && uint32(clamav) == uid
}
