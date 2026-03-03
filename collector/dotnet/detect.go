package dotnet

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DotNetProcess represents a detected .NET Core process on Linux.
type DotNetProcess struct {
	PID        int
	Comm       string
	SocketPath string // /tmp/dotnet-diagnostic-<pid>-<hash>-socket
}

// DetectProcesses scans for running .NET Core processes by looking for
// EventPipe diagnostic sockets in /tmp.
func DetectProcesses() []DotNetProcess {
	pattern := "/tmp/dotnet-diagnostic-*-socket"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}

	var procs []DotNetProcess
	for _, sockPath := range matches {
		pid := extractPIDFromSocket(sockPath)
		if pid <= 0 {
			continue
		}

		// Verify process still exists
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		commData, err := os.ReadFile(commPath)
		if err != nil {
			continue // process gone
		}
		comm := strings.TrimSpace(string(commData))

		procs = append(procs, DotNetProcess{
			PID:        pid,
			Comm:       comm,
			SocketPath: sockPath,
		})
	}

	return procs
}

// extractPIDFromSocket extracts the PID from a diagnostic socket path.
// Format: /tmp/dotnet-diagnostic-<pid>-<hash>-socket
func extractPIDFromSocket(path string) int {
	base := filepath.Base(path)
	// dotnet-diagnostic-1234-567890-socket
	if !strings.HasPrefix(base, "dotnet-diagnostic-") {
		return 0
	}
	rest := strings.TrimPrefix(base, "dotnet-diagnostic-")
	// rest = "1234-567890-socket"
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) < 1 {
		return 0
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return pid
}
