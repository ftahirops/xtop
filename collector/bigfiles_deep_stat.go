//go:build linux

package collector

import "syscall"

// syscall_stat is a thin alias that lets us depend on syscall.Stat_t's Dev
// field without Go's ParseFloat of syscall.Stat_t polluting the upper
// scanner code.
type syscall_stat = syscall.Stat_t

// lstatSyscall follows the lstat(2) convention — does not dereference
// symlinks — which is exactly what we want for cross-mount detection.
func lstatSyscall(path string, st *syscall_stat) error {
	return syscall.Lstat(path, st)
}
