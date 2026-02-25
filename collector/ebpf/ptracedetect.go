//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
)

type ptracedetectProbe struct {
	objs  ptracedetectObjects
	links []link.Link
}

// PtraceEventResult holds a ptrace syscall event from BPF.
type PtraceEventResult struct {
	TracerPID  uint32
	TracerComm string
	Request    uint64
	TargetPID  uint32
	Count      uint64
	Ts         uint64
}

func attachPtraceDetect() (*ptracedetectProbe, error) {
	var objs ptracedetectObjects
	if err := loadPtracedetectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load ptracedetect: %w", err)
	}

	l, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.HandleSysEnterPtrace, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach sys_enter_ptrace: %w", err)
	}

	return &ptracedetectProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *ptracedetectProbe) read() ([]PtraceEventResult, error) {
	var results []PtraceEventResult
	var key ptracedetectPtraceKey
	var val ptracedetectPtraceVal

	iter := p.objs.PtraceAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.Count == 0 {
			continue
		}
		// Convert [16]int8 to string
		var commBuf [16]byte
		for i, c := range val.TracerComm {
			commBuf[i] = byte(c)
		}
		tracerComm := strings.TrimRight(string(commBuf[:]), "\x00")

		results = append(results, PtraceEventResult{
			TracerPID:  key.TracerPid,
			TracerComm: tracerComm,
			Request:    val.Request,
			TargetPID:  key.TargetPid,
			Count:      val.Count,
			Ts:         val.Ts,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate ptrace_accum map: %w", err)
	}
	return results, nil
}

// readAndClear reads ptrace events and deletes them from the map.
func (p *ptracedetectProbe) readAndClear() ([]PtraceEventResult, error) {
	var results []PtraceEventResult
	var keys []ptracedetectPtraceKey
	var key ptracedetectPtraceKey
	var val ptracedetectPtraceVal

	iter := p.objs.PtraceAccum.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
		if val.Count == 0 {
			continue
		}
		var commBuf [16]byte
		for i, c := range val.TracerComm {
			commBuf[i] = byte(c)
		}
		tracerComm := strings.TrimRight(string(commBuf[:]), "\x00")

		results = append(results, PtraceEventResult{
			TracerPID:  key.TracerPid,
			TracerComm: tracerComm,
			Request:    val.Request,
			TargetPID:  key.TargetPid,
			Count:      val.Count,
			Ts:         val.Ts,
		})
	}
	// Delete all entries after reading
	for _, k := range keys {
		k2 := k
		_ = p.objs.PtraceAccum.Delete(&k2)
	}
	return results, nil
}

func (p *ptracedetectProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// ptraceRequestName maps PTRACE_* request codes to human-readable names.
func ptraceRequestName(req uint64) string {
	switch req {
	case 4:
		return "PTRACE_POKETEXT"
	case 5:
		return "PTRACE_POKEDATA"
	case 13:
		return "PTRACE_SETREGS"
	case 16:
		return "PTRACE_ATTACH"
	case 0x4206:
		return "PTRACE_SEIZE"
	default:
		return fmt.Sprintf("PTRACE_%d", req)
	}
}
