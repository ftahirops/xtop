package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
)

// JVMModule detects JVM processes via /tmp/hsperfdata_* files.
type JVMModule struct {
	detected []jvmProcess
	active   bool
	mu       sync.Mutex
}

type jvmProcess struct {
	PID      int
	Comm     string
	PerfPath string // /tmp/hsperfdata_<user>/<pid>
}

// NewJVMModule creates a new JVM runtime module.
func NewJVMModule() *JVMModule {
	return &JVMModule{}
}

func (m *JVMModule) Name() string        { return "jvm" }
func (m *JVMModule) DisplayName() string  { return "JVM" }

func (m *JVMModule) Detect(processes []model.ProcessMetrics) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build PID→comm map for cross-referencing
	procMap := make(map[int]string, len(processes))
	for _, p := range processes {
		procMap[p.PID] = p.Comm
	}

	// Scan /tmp/hsperfdata_*/*
	dirs, _ := filepath.Glob("/tmp/hsperfdata_*")
	var found []jvmProcess
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid <= 0 {
				continue
			}
			// Cross-reference with process list
			comm, ok := procMap[pid]
			if !ok {
				// Process might not be in top N; check /proc directly
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
				if err != nil {
					continue
				}
				comm = strings.TrimSpace(string(data))
			}
			found = append(found, jvmProcess{
				PID:      pid,
				Comm:     comm,
				PerfPath: filepath.Join(dir, e.Name()),
			})
		}
	}

	m.detected = found
	m.active = len(found) > 0
	return m.active
}

func (m *JVMModule) Collect() []model.RuntimeProcessMetrics {
	m.mu.Lock()
	procs := make([]jvmProcess, len(m.detected))
	copy(procs, m.detected)
	m.mu.Unlock()

	var result []model.RuntimeProcessMetrics
	for _, jp := range procs {
		perf := parseHsperfdata(jp.PerfPath)

		rss := readProcRSSMB(jp.PID)
		threads := readProcThreads(jp.PID)

		rpm := model.RuntimeProcessMetrics{
			PID:          jp.PID,
			Comm:         jp.Comm,
			Runtime:      "jvm",
			WorkingSetMB: rss,
			ThreadCount:  threads,
			Extra:        make(map[string]string),
		}

		if perf != nil {
			// GC metrics
			youngGC := perf.getCounter("sun.gc.collector.0.invocations")
			fullGC := perf.getCounter("sun.gc.collector.1.invocations")
			youngGCTime := perf.getCounter("sun.gc.collector.0.time") // ticks
			fullGCTime := perf.getCounter("sun.gc.collector.1.time")
			tickFreq := perf.getCounter("sun.os.hrt.frequency")

			rpm.GCCount = uint64(youngGC + fullGC)

			// GC pause percentage: (gc_time / frequency) / uptime * 100
			if tickFreq > 0 {
				totalGCTicks := youngGCTime + fullGCTime
				uptime := perf.getCounter("sun.os.hrt.ticks")
				if uptime > 0 {
					rpm.GCPausePct = float64(totalGCTicks) / float64(uptime) * 100
				}
			}

			// Heap
			heapUsed := perf.getHeapUsedBytes()
			heapCap := perf.getHeapCapacityBytes()
			rpm.GCHeapMB = float64(heapUsed) / (1024 * 1024)

			// Thread count from hsperfdata
			liveThreads := perf.getCounter("java.threads.live")
			if liveThreads > 0 {
				rpm.ThreadCount = int(liveThreads)
			}

			classLoaded := perf.getCounter("java.cls.loadedClasses")

			rpm.Extra["heap_max_mb"] = fmt.Sprintf("%.1f", float64(heapCap)/(1024*1024))
			rpm.Extra["young_gc_count"] = fmt.Sprintf("%d", youngGC)
			rpm.Extra["full_gc_count"] = fmt.Sprintf("%d", fullGC)
			rpm.Extra["class_loaded"] = fmt.Sprintf("%d", classLoaded)
		}

		result = append(result, rpm)
	}
	return result
}

func (m *JVMModule) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *JVMModule) ProcessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.detected)
}
