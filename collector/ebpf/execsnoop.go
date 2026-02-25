//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
)

type execsnoopProbe struct {
	objs  execsnoopObjects
	links []link.Link
}

// ExecEventResult holds a process execution event from BPF.
type ExecEventResult struct {
	PID      uint32
	PPID     uint32
	UID      uint32
	Comm     string
	Filename string
	Count    uint64
	Ts       uint64
}

func attachExecSnoop() (*execsnoopProbe, error) {
	var objs execsnoopObjects
	if err := loadExecsnoopObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load execsnoop: %w", err)
	}

	l, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach sched_process_exec: %w", err)
	}

	return &execsnoopProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *execsnoopProbe) read() ([]ExecEventResult, error) {
	var results []ExecEventResult
	var pid uint32
	var val execsnoopExecVal

	iter := p.objs.ExecAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		// Convert [16]int8 to string
		var commBuf [16]byte
		for i, c := range val.Comm {
			commBuf[i] = byte(c)
		}
		comm := strings.TrimRight(string(commBuf[:]), "\x00")

		// Convert [128]int8 to string
		var fnBuf [128]byte
		for i, c := range val.Filename {
			fnBuf[i] = byte(c)
		}
		filename := strings.TrimRight(string(fnBuf[:]), "\x00")

		results = append(results, ExecEventResult{
			PID:      pid,
			PPID:     val.Ppid,
			UID:      val.Uid,
			Comm:     comm,
			Filename: filename,
			Count:    val.Count,
			Ts:       val.Ts,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate exec_accum map: %w", err)
	}
	return results, nil
}

// readAndClear reads exec events and deletes them from the map.
func (p *execsnoopProbe) readAndClear() ([]ExecEventResult, error) {
	results, err := p.read()
	if err != nil {
		return results, err
	}
	for _, r := range results {
		pid := r.PID
		_ = p.objs.ExecAccum.Delete(&pid)
	}
	return results, nil
}

func (p *execsnoopProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
