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
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			// state 0A = LISTEN
			if fields[3] != "0A" {
				continue
			}
			// inode is field[9]
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
					// Try parsing as integer directly
					p, err := strconv.ParseInt(localParts[1], 16, 32)
					if err == nil && p > 0 {
						return int(p)
					}
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

// findConfigFile returns the first existing path from the list.
func findConfigFile(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
