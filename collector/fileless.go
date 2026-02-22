package collector

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// FilelessCollector detects processes running from memory (memfd_create or deleted executables)
// and correlates them with outbound network connections.
type FilelessCollector struct {
	mu       sync.Mutex
	cache    []model.FilelessProcess
	lastScan time.Time
}

const filelessScanInterval = 10 * time.Second

func (f *FilelessCollector) Name() string { return "fileless" }

func (f *FilelessCollector) Collect(snap *model.Snapshot) error {
	f.mu.Lock()
	needScan := time.Since(f.lastScan) >= filelessScanInterval
	f.mu.Unlock()

	if !needScan {
		f.mu.Lock()
		snap.Global.FilelessProcs = f.cache
		f.mu.Unlock()
		return nil
	}

	results := f.scan()

	f.mu.Lock()
	f.cache = results
	f.lastScan = time.Now()
	f.mu.Unlock()

	snap.Global.FilelessProcs = results
	return nil
}

// knownSafeComms are process names known to legitimately use memfd or deleted executables.
var knownSafeComms = map[string]bool{
	"chrome":          true,
	"chromium":        true,
	"electron":        true,
	"runc":            true,
	"containerd-shim": true,
	"crun":            true,
}

// knownSafePrefixes are path prefixes for executables that are likely upgrade leftovers.
var knownSafePrefixes = []string{
	"/usr/",
	"/lib/",
	"/sbin/",
	"/bin/",
	"/opt/",
}

func (f *FilelessCollector) scan() []model.FilelessProcess {
	selfPID := os.Getpid()

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	// Phase 1: find fileless processes
	var candidates []model.FilelessProcess

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 100 || pid == selfPID {
			continue
		}

		exePath, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}

		isMemFD := strings.HasPrefix(exePath, "/memfd:")
		isDeleted := !isMemFD && strings.HasSuffix(exePath, " (deleted)")

		if !isMemFD && !isDeleted {
			continue
		}

		// For deleted (non-memfd) executables, skip known safe paths (upgrade leftovers)
		if isDeleted {
			cleanPath := strings.TrimSuffix(exePath, " (deleted)")
			safe := false
			for _, prefix := range knownSafePrefixes {
				if strings.HasPrefix(cleanPath, prefix) {
					safe = true
					break
				}
			}
			if safe {
				continue
			}
		}

		comm := readComm(pid)

		// Skip known-safe process names
		if knownSafeComms[comm] {
			continue
		}

		rss := readRSS(pid)

		candidates = append(candidates, model.FilelessProcess{
			PID:       pid,
			Comm:      comm,
			ExePath:   exePath,
			IsMemFD:   isMemFD,
			IsDeleted: isDeleted,
			RSS:       rss,
		})
	}

	if len(candidates) == 0 {
		return nil
	}

	// Phase 2: network correlation (only for discovered fileless PIDs)
	tcpConns := parseTCPConns()

	for i := range candidates {
		pid := candidates[i].PID
		fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		uniqueIPs := make(map[string]bool)
		netConns := 0

		for _, fe := range fdEntries {
			target, err := os.Readlink(filepath.Join(fdDir, fe.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") {
				continue
			}
			// Extract inode from "socket:[12345]"
			inodeStr := target[8 : len(target)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			conn, ok := tcpConns[inode]
			if !ok {
				continue
			}
			netConns++
			if len(uniqueIPs) < 5 {
				uniqueIPs[conn.remoteIP] = true
			}
		}

		candidates[i].NetConns = netConns
		for ip := range uniqueIPs {
			candidates[i].RemoteIPs = append(candidates[i].RemoteIPs, ip)
		}
		sort.Strings(candidates[i].RemoteIPs)
	}

	// Sort: memfd first, then by NetConns descending
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].IsMemFD != candidates[j].IsMemFD {
			return candidates[i].IsMemFD
		}
		return candidates[i].NetConns > candidates[j].NetConns
	})

	if len(candidates) > 20 {
		candidates = candidates[:20]
	}

	return candidates
}

// readRSS reads VmRSS from /proc/PID/status and returns it in bytes.
func readRSS(pid int) uint64 {
	lines, err := util.ReadFileLines(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val := util.ParseUint64(fields[1])
				// VmRSS is in kB
				return val * 1024
			}
		}
	}
	return 0
}

// tcpConn holds a parsed TCP connection for network correlation.
type tcpConn struct {
	remoteIP string
}

// parseTCPConns parses /proc/net/tcp and /proc/net/tcp6 for ESTABLISHED and SYN_SENT
// connections to non-loopback remote IPs. Returns a map of inode -> connection info.
func parseTCPConns() map[uint64]tcpConn {
	conns := make(map[uint64]tcpConn)

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

			// State: 01=ESTABLISHED, 02=SYN_SENT
			stateHex := fields[3]
			if stateHex != "01" && stateHex != "02" {
				continue
			}

			inode := util.ParseUint64(fields[9])
			if inode == 0 {
				continue
			}

			remIP := filelessParseRemoteIP(fields[2])
			if remIP == "" {
				continue
			}

			// Skip loopback
			if remIP == "127.0.0.1" || strings.HasPrefix(remIP, "127.") || remIP == "::1" || remIP == "0.0.0.0" {
				continue
			}

			conns[inode] = tcpConn{remoteIP: remIP}
		}
	}

	return conns
}

// filelessParseRemoteIP extracts the remote IP from a /proc/net/tcp rem_address field.
func filelessParseRemoteIP(remAddr string) string {
	parts := strings.SplitN(remAddr, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	if len(b) == 16 {
		// IPv6 — check for IPv4-mapped (::ffff:x.x.x.x)
		allZero := true
		for i := 0; i < 10; i++ {
			if b[i] != 0 {
				allZero = false
				break
			}
		}
		if allZero && b[10] == 0xff && b[11] == 0xff {
			return fmt.Sprintf("%d.%d.%d.%d", b[12], b[13], b[14], b[15])
		}
		// Full IPv6
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(b[0])<<8|uint16(b[1]),
			uint16(b[2])<<8|uint16(b[3]),
			uint16(b[4])<<8|uint16(b[5]),
			uint16(b[6])<<8|uint16(b[7]),
			uint16(b[8])<<8|uint16(b[9]),
			uint16(b[10])<<8|uint16(b[11]),
			uint16(b[12])<<8|uint16(b[13]),
			uint16(b[14])<<8|uint16(b[15]))
	}
	return ""
}
