package collector

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcDeepInfo holds deep per-PID metrics from /proc.
type ProcDeepInfo struct {
	PID     int
	PPID    int
	Comm    string
	Cmdline string
	State   string
	Cgroup  string
	Service string // resolved from cgroup

	// Memory from /proc/PID/status
	VmPeak uint64
	VmSize uint64
	VmRSS  uint64
	VmSwap uint64

	// IO from /proc/PID/io
	ReadBytes  uint64
	WriteBytes uint64
	SyscR      uint64
	SyscW      uint64

	// File descriptors
	FDCount int
	FDLimit uint64
	TopFDs  []FDInfo

	// Network connections
	TCPConns []ConnInfo
	UDPConns []ConnInfo

	// Timing
	StartTime time.Time
	Uptime    time.Duration

	// Threads
	NumThreads int
}

// FDInfo describes an open file descriptor.
type FDInfo struct {
	FD     int
	Target string // readlink result
}

// ConnInfo describes a network connection.
type ConnInfo struct {
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	State      string
}

// CollectProcDeep reads deep metrics for a single PID.
func CollectProcDeep(pid int) (*ProcDeepInfo, error) {
	procDir := fmt.Sprintf("/proc/%d", pid)
	if _, err := os.Stat(procDir); err != nil {
		return nil, fmt.Errorf("process %d not found", pid)
	}

	info := &ProcDeepInfo{PID: pid}

	// /proc/PID/status
	if data, err := os.ReadFile(filepath.Join(procDir, "status")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":\t", 2)
			if len(parts) != 2 {
				continue
			}
			key, val := parts[0], strings.TrimSpace(parts[1])
			switch key {
			case "Name":
				info.Comm = val
			case "State":
				info.State = val
			case "PPid":
				info.PPID, _ = strconv.Atoi(val)
			case "Threads":
				info.NumThreads, _ = strconv.Atoi(val)
			case "VmPeak":
				info.VmPeak = parseKBtoBytes(val)
			case "VmSize":
				info.VmSize = parseKBtoBytes(val)
			case "VmRSS":
				info.VmRSS = parseKBtoBytes(val)
			case "VmSwap":
				info.VmSwap = parseKBtoBytes(val)
			}
		}
	}

	// /proc/PID/cmdline
	if data, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		info.Cmdline = strings.ReplaceAll(string(data), "\x00", " ")
		info.Cmdline = strings.TrimSpace(info.Cmdline)
	}

	// /proc/PID/io
	if data, err := os.ReadFile(filepath.Join(procDir, "io")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) != 2 {
				continue
			}
			val, _ := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
			switch parts[0] {
			case "read_bytes":
				info.ReadBytes = val
			case "write_bytes":
				info.WriteBytes = val
			case "syscr":
				info.SyscR = val
			case "syscw":
				info.SyscW = val
			}
		}
	}

	// /proc/PID/cgroup
	if data, err := os.ReadFile(filepath.Join(procDir, "cgroup")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 {
			// cgroup v2: single line "0::/path"
			parts := strings.SplitN(lines[0], "::", 2)
			if len(parts) == 2 {
				info.Cgroup = parts[1]
			} else {
				// cgroup v1: take the last line
				parts = strings.SplitN(lines[len(lines)-1], ":", 3)
				if len(parts) == 3 {
					info.Cgroup = parts[2]
				}
			}
			info.Service = resolveService(info.Cgroup)
		}
	}

	// /proc/PID/fd — count + top FDs
	fdDir := filepath.Join(procDir, "fd")
	if entries, err := os.ReadDir(fdDir); err == nil {
		info.FDCount = len(entries)
		maxFDs := 20
		if len(entries) < maxFDs {
			maxFDs = len(entries)
		}
		info.TopFDs = make([]FDInfo, 0, maxFDs)
		for i := 0; i < maxFDs; i++ {
			fdNum, _ := strconv.Atoi(entries[i].Name())
			target, _ := os.Readlink(filepath.Join(fdDir, entries[i].Name()))
			info.TopFDs = append(info.TopFDs, FDInfo{FD: fdNum, Target: target})
		}
	}

	// /proc/PID/limits — FD soft limit
	if data, err := os.ReadFile(filepath.Join(procDir, "limits")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Max open files") {
				fields := strings.Fields(line)
				// "Max open files   1024   1048576   files"
				if len(fields) >= 5 {
					info.FDLimit, _ = strconv.ParseUint(fields[3], 10, 64)
				}
			}
		}
	}

	// /proc/PID/net/tcp — TCP connections
	info.TCPConns = readProcNetConns(filepath.Join(procDir, "net/tcp"))

	// /proc/PID/net/udp — UDP connections
	info.UDPConns = readProcNetConns(filepath.Join(procDir, "net/udp"))

	// /proc/PID/stat — start time
	if data, err := os.ReadFile(filepath.Join(procDir, "stat")); err == nil {
		info.StartTime, info.Uptime = parseStartTime(string(data))
	}

	return info, nil
}

// parseKBtoBytes parses "12345 kB" to bytes.
func parseKBtoBytes(s string) uint64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[0], 10, 64)
	if len(fields) > 1 && strings.ToLower(fields[1]) == "kb" {
		return v * 1024
	}
	return v
}

// resolveService extracts a service name from a cgroup path.
func resolveService(cgPath string) string {
	// systemd: /system.slice/nginx.service
	if strings.Contains(cgPath, ".service") {
		parts := strings.Split(cgPath, "/")
		for _, p := range parts {
			if strings.HasSuffix(p, ".service") {
				return strings.TrimSuffix(p, ".service")
			}
		}
	}
	// Docker: /docker/<id>
	if strings.Contains(cgPath, "/docker/") {
		parts := strings.Split(cgPath, "/docker/")
		if len(parts) > 1 && len(parts[1]) >= 12 {
			return "docker:" + parts[1][:12]
		}
	}
	// k8s: /kubepods/.../<pod>/<container>
	if strings.Contains(cgPath, "/kubepods") {
		parts := strings.Split(cgPath, "/")
		if len(parts) > 0 {
			return "k8s:" + parts[len(parts)-1]
		}
	}
	return ""
}

// readProcNetConns parses /proc/PID/net/tcp or /proc/PID/net/udp.
func readProcNetConns(path string) []ConnInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil
	}

	conns := make([]ConnInfo, 0, len(lines)-1)
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddr, localPort := parseHexAddr(fields[1])
		remoteAddr, remotePort := parseHexAddr(fields[2])
		state := tcpStateStr(fields[3])

		conns = append(conns, ConnInfo{
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
		})
	}
	return conns
}

// parseHexAddr parses "0100007F:0050" -> ("127.0.0.1", 80).
func parseHexAddr(s string) (string, int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	// Parse hex IP (little-endian)
	ipHex := parts[0]
	if len(ipHex) == 8 {
		b0, _ := strconv.ParseUint(ipHex[6:8], 16, 8)
		b1, _ := strconv.ParseUint(ipHex[4:6], 16, 8)
		b2, _ := strconv.ParseUint(ipHex[2:4], 16, 8)
		b3, _ := strconv.ParseUint(ipHex[0:2], 16, 8)
		ip := net.IPv4(byte(b0), byte(b1), byte(b2), byte(b3))
		port, _ := strconv.ParseUint(parts[1], 16, 16)
		return ip.String(), int(port)
	}
	port, _ := strconv.ParseUint(parts[1], 16, 16)
	return ipHex, int(port)
}

// tcpStateStr converts a hex TCP state to string.
func tcpStateStr(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}

// parseStartTime extracts process start time from /proc/PID/stat.
func parseStartTime(statData string) (time.Time, time.Duration) {
	// Field 22 (1-indexed) is starttime in clock ticks since boot.
	// Find the closing ')' of comm field, then count fields.
	idx := strings.LastIndex(statData, ")")
	if idx < 0 {
		return time.Time{}, 0
	}
	rest := strings.TrimSpace(statData[idx+1:])
	fields := strings.Fields(rest)
	// Field 22 is index 19 in rest (fields after comm: state=0, ppid=1, ... starttime=19)
	if len(fields) < 20 {
		return time.Time{}, 0
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, 0
	}

	// Read boot time
	bootData, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, 0
	}
	var bootSec int64
	for _, line := range strings.Split(string(bootData), "\n") {
		if strings.HasPrefix(line, "btime ") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				bootSec, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	}
	if bootSec == 0 {
		return time.Time{}, 0
	}

	ticksPerSec := int64(100) // SC_CLK_TCK
	startEpoch := bootSec + int64(ticks)/ticksPerSec
	startTime := time.Unix(startEpoch, 0)
	uptime := time.Since(startTime)
	return startTime, uptime
}
