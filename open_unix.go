//go:build unix

package avscan

import "syscall"

const openNonblock = syscall.O_NONBLOCK
