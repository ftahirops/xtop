package dotnet

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// Collector discovers and collects metrics from .NET Core processes on Linux.
type Collector struct {
	processes   []DotNetProcess
	lastScan    time.Time
	scanInterval time.Duration
	mu          sync.Mutex
}

// NewCollector creates a new .NET Core collector.
func NewCollector() *Collector {
	return &Collector{
		scanInterval: 30 * time.Second,
	}
}

// Name returns the collector name.
func (c *Collector) Name() string { return "dotnet" }

// Collect gathers .NET Core metrics into the snapshot.
func (c *Collector) Collect(snap *model.Snapshot) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Rescan for .NET processes periodically
	if time.Since(c.lastScan) >= c.scanInterval {
		c.processes = DetectProcesses()
		c.lastScan = time.Now()
	}

	if len(c.processes) == 0 {
		return nil
	}

	metrics := make([]model.DotNetProcessMetrics, 0, len(c.processes))
	for _, proc := range c.processes {
		client := NewEventPipeClient(proc.PID, proc.SocketPath)
		if err := client.Connect(); err != nil {
			continue
		}

		counters, err := client.RequestCounters()
		client.Close()
		if err != nil {
			continue
		}
		counters.Comm = proc.Comm

		metrics = append(metrics, model.DotNetProcessMetrics{
			PID:              proc.PID,
			Comm:             proc.Comm,
			GCHeapSizeMB:     counters.GCHeapSizeMB,
			Gen0GCCount:      counters.Gen0GCCount,
			Gen1GCCount:      counters.Gen1GCCount,
			Gen2GCCount:      counters.Gen2GCCount,
			TimeInGCPct:      counters.TimeInGCPct,
			AllocRateMBs:     counters.AllocRateMBs,
			ThreadPoolCount:  counters.ThreadPoolCount,
			ThreadPoolQueue:  counters.ThreadPoolQueue,
			ExceptionCount:   counters.ExceptionCount,
			MonitorLockCount: counters.MonitorLockCount,
			WorkingSetMB:     counters.WorkingSetMB,
			RequestsPerSec:   counters.RequestsPerSec,
			CurrentRequests:  counters.CurrentRequests,
		})
	}

	snap.Global.DotNet = metrics
	return nil
}

// readProcFile reads a file from /proc/<pid>/<name>.
func readProcFile(pid int, name string) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseVmRSS extracts VmRSS from /proc/PID/status in bytes.
func parseVmRSS(status string) float64 {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseFloat(fields[1], 64)
				if len(fields) >= 3 && strings.ToLower(fields[2]) == "kb" {
					return val * 1024
				}
				return val
			}
		}
	}
	return 0
}
