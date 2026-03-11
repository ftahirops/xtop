//go:build linux

package apps

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

)

// countTCPConnections counts established TCP connections to a given local port.
// Parses /proc/net/tcp (and tcp6) looking for connections in ESTABLISHED state (0A=LISTEN, 01=ESTABLISHED).
func countTCPConnections(port int) int {
	count := 0
	portHex := fmt.Sprintf("%04X", port)

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			// local_address is field[1], format: IP:PORT
			localParts := strings.Split(fields[1], ":")
			if len(localParts) != 2 {
				continue
			}
			if localParts[1] == portHex {
				// state field[3]: 01=ESTABLISHED, 0A=LISTEN
				if fields[3] == "01" {
					count++
				}
			}
		}
		f.Close()
	}
	return count
}

// countTCPListeners counts LISTEN sockets on a given port.
func countTCPListeners(port int) int {
	count := 0
	portHex := fmt.Sprintf("%04X", port)

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			localParts := strings.Split(fields[1], ":")
			if len(localParts) != 2 {
				continue
			}
			if localParts[1] == portHex && fields[3] == "0A" {
				count++
			}
		}
		f.Close()
	}
	return count
}

// findListeningPort scans /proc/net/tcp for a LISTEN socket owned by pid.
// Returns the port number, or 0 if not found.
func findListeningPort(pid int) int {
	// Get inodes for this PID's sockets
	inodes := make(map[string]bool)
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") {
			inode := strings.TrimPrefix(strings.TrimSuffix(link, "]"), "socket:[")
			inodes[inode] = true
		}
	}
	if len(inodes) == 0 {
		return 0
	}

	// Scan /proc/net/tcp for LISTEN sockets matching our inodes
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if port := scanTCPForInode(path, inodes); port > 0 {
			return port
		}
	}
	return 0
}

// scanTCPForInode scans a /proc/net/tcp file for LISTEN sockets matching given inodes.
func scanTCPForInode(path string, inodes map[string]bool) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		if inodes[fields[9]] {
			localParts := strings.Split(fields[1], ":")
			if len(localParts) == 2 {
				portBytes, err := hex.DecodeString(localParts[1])
				if err == nil && len(portBytes) == 2 {
					port := int(portBytes[0])<<8 | int(portBytes[1])
					if port > 0 {
						return port
					}
				}
				p, err := strconv.ParseInt(localParts[1], 16, 32)
				if err == nil && p > 0 {
					return int(p)
				}
			}
		}
	}
	return 0
}

// readProcRSS reads VmRSS from /proc/PID/status in MB.
func readProcRSS(pid int) float64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseFloat(fields[1], 64)
				return kb / 1024
			}
		}
	}
	return 0
}

// readProcThreads reads thread count from /proc/PID/status.
func readProcThreads(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Threads:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.Atoi(fields[1])
				return v
			}
		}
	}
	return 0
}

// readProcFDs counts open file descriptors for a PID.
func readProcFDs(pid int) int {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0
	}
	return len(entries)
}

// readProcCmdline reads /proc/PID/cmdline as a single string.
func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// Replace null bytes with spaces
	s := strings.ReplaceAll(string(data), "\x00", " ")
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.TrimSpace(s)
}

// readProcUptime returns uptime in seconds for a PID.
func readProcUptime(pid int) int64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	ci := strings.LastIndex(s, ")")
	if ci < 0 || ci+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[ci+2:])
	if len(fields) <= 19 {
		return 0
	}
	startTicks, _ := strconv.ParseUint(fields[19], 10, 64)
	if startTicks == 0 {
		return 0
	}

	// Read boot time
	statData, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	var bootTime float64
	for _, line := range strings.Split(string(statData), "\n") {
		if strings.HasPrefix(line, "btime ") {
			bootTime, _ = strconv.ParseFloat(strings.Fields(line)[1], 64)
			break
		}
	}
	if bootTime == 0 {
		return 0
	}

	startSec := bootTime + float64(startTicks)/100
	now := float64(time.Now().Unix())
	return int64(now - startSec)
}

// readProcCPUTicks reads utime+stime from /proc/PID/stat (fields 13+14 after the comm field).
// Returns total CPU ticks (utime + stime).
func readProcCPUTicks(pid int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	ci := strings.LastIndex(s, ")")
	if ci < 0 || ci+2 >= len(s) {
		return 0
	}
	// Fields after ")": state(0), ppid(1), pgrp(2), session(3), tty(4), tpgid(5),
	// flags(6), minflt(7), cminflt(8), majflt(9), cmajflt(10), utime(11), stime(12)
	fields := strings.Fields(s[ci+2:])
	if len(fields) < 13 {
		return 0
	}
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)
	return utime + stime
}

// findAllListeningPorts finds all listening ports owned by a PID.
func findAllListeningPorts(pid int) []int {
	// Get inodes for this PID's sockets
	inodes := make(map[string]bool)
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") {
			inode := strings.TrimPrefix(strings.TrimSuffix(link, "]"), "socket:[")
			inodes[inode] = true
		}
	}
	if len(inodes) == 0 {
		return nil
	}

	seen := make(map[int]bool)
	var ports []int
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			flds := strings.Fields(scanner.Text())
			if len(flds) < 10 {
				continue
			}
			if flds[3] != "0A" { // LISTEN
				continue
			}
			if !inodes[flds[9]] {
				continue
			}
			localParts := strings.Split(flds[1], ":")
			if len(localParts) == 2 {
				portBytes, err := hex.DecodeString(localParts[1])
				if err == nil && len(portBytes) == 2 {
					p := int(portBytes[0])<<8 | int(portBytes[1])
					if p > 0 && !seen[p] {
						seen[p] = true
						ports = append(ports, p)
					}
					continue
				}
				pv, err := strconv.ParseInt(localParts[1], 16, 32)
				if err == nil && pv > 0 && !seen[int(pv)] {
					seen[int(pv)] = true
					ports = append(ports, int(pv))
				}
			}
		}
		f.Close()
	}
	return ports
}

// countChildProcesses counts child processes with given comm name.
func countChildProcesses(parentPID int, comm string) int {
	count := 0
	entries, err := procEntries()
	if err != nil {
		return 0
	}
	for _, pid := range entries {
		if pid == parentPID {
			continue
		}
		ppid, pcomm := readPPIDComm(pid)
		if ppid == parentPID && pcomm == comm {
			count++
		}
	}
	return count
}

// findConfigFile returns the first existing path from the list.
func findConfigFile(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
