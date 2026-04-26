//go:build linux

package collector

import (
	"syscall"
)

// ioprioClass/value constants from Linux include/uapi/linux/ioprio.h.
// Class 3 (IDLE) means the kernel dispatches IO for this thread only when
// nothing else wants the disk — the polite-scanner primary safety belt.
const (
	ioprioClassShift = 13
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	sysIOPrioSet     = 251 // on amd64 / aarch64
)

// setIOPrioIdle puts the CURRENT thread into the IDLE IO class. Any IO that
// thread issues (via stat/readdir/openat on behalf of the filepath walker)
// will be kernel-preempted by any normal IO from other processes.
//
// Returns nil on success. On non-Linux builds the symbol isn't compiled —
// callers get a fallback no-op via the stub in ioprio_other.go.
func setIOPrioIdle() error {
	value := ioprioClassIdle<<ioprioClassShift | 7
	_, _, errno := syscall.Syscall(sysIOPrioSet, ioprioWhoProcess, 0, uintptr(value))
	if errno != 0 {
		return errno
	}
	return nil
}

// setNicePolite lowers the CPU scheduling priority of the current thread to
// the lowest non-idle level (nice 19). Combined with setIOPrioIdle, this
// keeps the deep scanner from competing with any user workload.
func setNicePolite() error {
	return syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
}
