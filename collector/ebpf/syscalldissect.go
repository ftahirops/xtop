//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type syscalldissectProbe struct {
	objs  syscalldissectObjects
	links []link.Link
}

// SyscallDissectResult holds raw per-PID per-syscall time data.
type SyscallDissectResult struct {
	PID       uint32
	SyscallNr uint32
	Comm      string
	TotalNs   uint64
	Count     uint32
	MaxNs     uint32
}

func attachSyscallDissect() (*syscalldissectProbe, error) {
	var objs syscalldissectObjects
	if err := loadSyscalldissectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load syscalldissect: %w", err)
	}

	l1, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.HandleSysEnter, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach sys_enter: %w", err)
	}

	l2, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.HandleSysExit, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach sys_exit: %w", err)
	}

	return &syscalldissectProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *syscalldissectProbe) read() ([]SyscallDissectResult, error) {
	var results []SyscallDissectResult
	var key syscalldissectScKey
	var val syscalldissectScVal

	iter := p.objs.ScAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.TotalNs == 0 {
			continue
		}
		results = append(results, SyscallDissectResult{
			PID:       key.Pid,
			SyscallNr: key.SyscallNr,
			Comm:      readComm(key.Pid),
			TotalNs:   val.TotalNs,
			Count:     val.Count,
			MaxNs:     val.MaxNs,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate sc_accum map: %w", err)
	}
	return results, nil
}

func (p *syscalldissectProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// ResolveSyscall returns the name and group for a syscall number (x86_64).
func ResolveSyscall(nr uint32) (string, string) {
	name, ok := syscallNames[nr]
	if !ok {
		name = fmt.Sprintf("sys_%d", nr)
	}
	group, ok := syscallGroups[nr]
	if !ok {
		group = "other"
	}
	return name, group
}

// syscallNames maps x86_64 syscall numbers to names.
var syscallNames = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	5:   "fstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	23:  "select",
	35:  "nanosleep",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	56:  "clone",
	57:  "fork",
	59:  "execve",
	62:  "kill",
	72:  "fcntl",
	73:  "flock",
	78:  "getdents",
	79:  "getcwd",
	87:  "unlink",
	202: "futex",
	217: "getdents64",
	228: "clock_gettime",
	230: "clock_nanosleep",
	232: "epoll_wait",
	257: "openat",
	262: "newfstatat",
	270: "pselect6",
	271: "ppoll",
	280: "timerfd_settime",
	281: "timerfd_gettime",
	284: "eventfd",
	288: "accept4",
	291: "epoll_create1",
	293: "pipe2",
	295: "preadv",
	296: "pwritev",
	302: "prlimit64",
	318: "getrandom",
	435: "clone3",
}

// syscallGroups maps x86_64 syscall numbers to group categories.
var syscallGroups = map[uint32]string{
	0:   "read",
	17:  "read",
	19:  "read",
	45:  "read",
	47:  "read",
	295: "read",
	1:   "write",
	18:  "write",
	20:  "write",
	44:  "write",
	46:  "write",
	296: "write",
	202: "lock/sync",
	7:   "poll",
	23:  "poll",
	232: "poll",
	270: "poll",
	271: "poll",
	35:  "sleep",
	230: "sleep",
	2:   "open/close",
	3:   "open/close",
	87:  "open/close",
	257: "open/close",
	9:   "mmap",
	10:  "mmap",
	11:  "mmap",
}

// WellKnownPort returns a human-readable service name for common TCP ports.
func WellKnownPort(port uint16) string {
	switch port {
	case 80:
		return "http"
	case 443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 6379:
		return "redis"
	case 27017:
		return "mongo"
	case 9200:
		return "elasticsearch"
	case 9092:
		return "kafka"
	case 2379:
		return "etcd"
	case 11211:
		return "memcached"
	case 5672:
		return "amqp"
	case 6443:
		return "k8s-api"
	case 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	case 22:
		return "ssh"
	case 53:
		return "dns"
	default:
		return ""
	}
}
