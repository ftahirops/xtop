package runtime

import (
	"fmt"
	"sync"

	"github.com/ftahirops/xtop/collector/dotnet"
	"github.com/ftahirops/xtop/model"
)

// DotNetModule wraps the existing collector/dotnet package as a RuntimeModule.
type DotNetModule struct {
	inner    *dotnet.Collector
	active   bool
	procCount int
	mu       sync.Mutex
}

// NewDotNetModule creates a new .NET runtime module.
func NewDotNetModule() *DotNetModule {
	return &DotNetModule{
		inner: dotnet.NewCollector(),
	}
}

func (m *DotNetModule) Name() string        { return "dotnet" }
func (m *DotNetModule) DisplayName() string  { return ".NET" }

func (m *DotNetModule) Detect(processes []model.ProcessMetrics) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	procs := dotnet.DetectProcesses()
	m.active = len(procs) > 0
	m.procCount = len(procs)
	return m.active
}

func (m *DotNetModule) Collect() []model.RuntimeProcessMetrics {
	// Use the inner collector's Collect method via a temporary snapshot
	tmpSnap := &model.Snapshot{}
	if err := m.inner.Collect(tmpSnap); err != nil {
		return nil
	}

	var result []model.RuntimeProcessMetrics
	for _, dn := range tmpSnap.Global.DotNet {
		totalGC := dn.Gen0GCCount + dn.Gen1GCCount + dn.Gen2GCCount
		result = append(result, model.RuntimeProcessMetrics{
			PID:          dn.PID,
			Comm:         dn.Comm,
			Runtime:      "dotnet",
			WorkingSetMB: dn.WorkingSetMB,
			ThreadCount:  dn.ThreadPoolCount,
			GCHeapMB:     dn.GCHeapSizeMB,
			GCPausePct:   dn.TimeInGCPct,
			GCCount:      totalGC,
			AllocRateMBs: dn.AllocRateMBs,
			Extra: map[string]string{
				"threadpool_count":  fmt.Sprintf("%d", dn.ThreadPoolCount),
				"threadpool_queue":  fmt.Sprintf("%d", dn.ThreadPoolQueue),
				"exception_count":   fmt.Sprintf("%d", dn.ExceptionCount),
				"monitor_lock_count": fmt.Sprintf("%d", dn.MonitorLockCount),
				"requests_per_sec":  fmt.Sprintf("%.1f", dn.RequestsPerSec),
				"current_requests":  fmt.Sprintf("%d", dn.CurrentRequests),
			},
		})
	}
	return result
}

func (m *DotNetModule) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *DotNetModule) ProcessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.procCount
}
