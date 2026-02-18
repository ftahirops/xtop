//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type lockwaitProbe struct {
	objs  lockwaitObjects
	links []link.Link
}

// LockWaitResult holds raw lock contention data for one process.
type LockWaitResult struct {
	PID         uint32
	Comm        string
	TotalWaitNs uint64
	Count       uint32
}

func attachLockWait() (*lockwaitProbe, error) {
	var objs lockwaitObjects
	if err := loadLockwaitObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load lockwait: %w", err)
	}

	l1, err := link.Tracepoint("syscalls", "sys_enter_futex", objs.HandleFutexEnter, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach sys_enter_futex: %w", err)
	}

	l2, err := link.Tracepoint("syscalls", "sys_exit_futex", objs.HandleFutexExit, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach sys_exit_futex: %w", err)
	}

	return &lockwaitProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *lockwaitProbe) read() ([]LockWaitResult, error) {
	var results []LockWaitResult
	var pid uint32
	var val lockwaitLockVal

	iter := p.objs.FutexAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.TotalWaitNs == 0 {
			continue
		}
		results = append(results, LockWaitResult{
			PID:         pid,
			Comm:        readComm(pid),
			TotalWaitNs: val.TotalWaitNs,
			Count:       val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate futex map: %w", err)
	}
	return results, nil
}

func (p *lockwaitProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
