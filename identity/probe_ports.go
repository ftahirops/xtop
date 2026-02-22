package identity

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// Well-known port to service name mapping.
var wellKnownPorts = map[int]string{
	22:    "ssh",
	25:    "postfix",
	53:    "dns",
	80:    "http",
	443:   "https",
	587:   "smtp-submission",
	993:   "imaps",
	995:   "pop3s",
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	9090:  "prometheus",
	9100:  "node-exporter",
	3000:  "grafana",
	27017: "mongodb",
	2379:  "etcd",
	6443:  "k8s-api",
	10250: "kubelet",
}

// listenInfo holds a listening port and its socket inode.
type listenInfo struct {
	port  int
	inode uint64
}

// probeListeningPorts reads /proc/net/tcp, tcp6, udp, and udp6 for listening sockets
// and maps them to services. Reuses the same hex parsing as collector/socket.go.
func probeListeningPorts(id *model.ServerIdentity) {
	var listeners []listenInfo

	// TCP: state 0x0A = LISTEN
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		lines, err := util.ReadFileLines(path)
		if err != nil {
			continue
		}
		for _, line := range lines[1:] { // skip header
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			stateBytes, err := hex.DecodeString(fields[3])
			if err != nil || len(stateBytes) == 0 {
				continue
			}
			if int(stateBytes[0]) != 0x0A {
				continue
			}
			port := parseLocalPort(fields[1])
			if port == 0 {
				continue
			}
			inode := util.ParseUint64(fields[9])
			listeners = append(listeners, listenInfo{port: port, inode: inode})
		}
	}

	// UDP: state 0x07 = UNCONN (listening). UDP uses local_address 00000000:PORT
	// for wildcard binds or specific address binds.
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		lines, err := util.ReadFileLines(path)
		if err != nil {
			continue
		}
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			stateBytes, err := hex.DecodeString(fields[3])
			if err != nil || len(stateBytes) == 0 {
				continue
			}
			// UDP state 07 = UNCONN (bound, listening)
			if int(stateBytes[0]) != 0x07 {
				continue
			}
			port := parseLocalPort(fields[1])
			if port == 0 {
				continue
			}
			inode := util.ParseUint64(fields[9])
			listeners = append(listeners, listenInfo{port: port, inode: inode})
		}
	}

	// Deduplicate ports (tcp + tcp6 can duplicate)
	seenPorts := make(map[int]bool)
	// Resolve inodes to PIDs
	inodeToPID := resolveInodesToPIDs(listeners)

	for _, l := range listeners {
		if seenPorts[l.port] {
			continue
		}
		seenPorts[l.port] = true

		svcName := wellKnownPorts[l.port]
		if svcName == "" {
			svcName = fmt.Sprintf("port-%d", l.port)
		}

		svc := findOrCreateService(id, svcName)
		svc.Running = true
		// Add port if not already present
		hasPort := false
		for _, p := range svc.Ports {
			if p == l.port {
				hasPort = true
				break
			}
		}
		if !hasPort {
			svc.Ports = append(svc.Ports, l.port)
		}

		// Attach PID info
		if pid, ok := inodeToPID[l.inode]; ok && pid > 0 {
			comm := readComm(pid)
			if comm != "" {
				svc.Name = comm // override generic port name with actual process name
				if svc.Extra == nil {
					svc.Extra = make(map[string]string)
				}
				svc.Extra["pid"] = fmt.Sprintf("%d", pid)
			}
		}
	}
}

// parseLocalPort extracts port from hex-encoded local_address field.
func parseLocalPort(localAddr string) int {
	parts := strings.SplitN(localAddr, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	b, err := hex.DecodeString(parts[1])
	if err != nil || len(b) < 2 {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

// resolveInodesToPIDs maps socket inodes to PIDs by scanning /proc/*/fd.
func resolveInodesToPIDs(listeners []listenInfo) map[uint64]int {
	result := make(map[uint64]int)
	if len(listeners) == 0 {
		return result
	}

	// Build target set
	targets := make(map[string]uint64)
	for _, l := range listeners {
		if l.inode > 0 {
			targets[fmt.Sprintf("socket:[%d]", l.inode)] = l.inode
		}
	}
	if len(targets) == 0 {
		return result
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}

	matched := 0
	total := len(targets)
	for _, pe := range procEntries {
		if matched >= total {
			break
		}
		if !pe.IsDir() {
			continue
		}
		pid := util.ParseInt(pe.Name())
		if pid < 1 {
			continue
		}
		fdDir := filepath.Join("/proc", pe.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fe := range fdEntries {
			target, err := os.Readlink(filepath.Join(fdDir, fe.Name()))
			if err != nil {
				continue
			}
			if inode, ok := targets[target]; ok {
				result[inode] = pid
				matched++
			}
		}
	}
	return result
}

// readComm reads /proc/PID/comm.
func readComm(pid int) string {
	content, err := util.ReadFileString(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(content)
}

// findOrCreateService finds an existing service by name or creates a new one.
func findOrCreateService(id *model.ServerIdentity, name string) *model.DetectedService {
	for i := range id.Services {
		if id.Services[i].Name == name {
			return &id.Services[i]
		}
	}
	id.Services = append(id.Services, model.DetectedService{Name: name})
	return &id.Services[len(id.Services)-1]
}
