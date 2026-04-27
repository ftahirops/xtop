package engine

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ─── Adaptive Threshold Engine ──────────────────────────────────────────────
//
// Learns per-workload thresholds from historical metric distributions.
// Instead of hardcoded constants, thresholds adapt to the workload's normal
// operating envelope. Supports workload types: web, database, cache, batch,
// message_queue, kubernetes, and unknown.

// WorkloadType identifies the kind of workload running on the host.
type WorkloadType string

const (
	WorkloadWeb          WorkloadType = "web"
	WorkloadDatabase     WorkloadType = "database"
	WorkloadCache        WorkloadType = "cache"
	WorkloadBatch        WorkloadType = "batch"
	WorkloadMessageQueue WorkloadType = "message_queue"
	WorkloadKubernetes   WorkloadType = "kubernetes"
	WorkloadUnknown      WorkloadType = "unknown"
)

// AdaptiveThresholdDB stores learned thresholds per workload type.
type AdaptiveThresholdDB struct {
	mu         sync.RWMutex
	workloads  map[WorkloadType]*workloadProfile
	dataDir    string
	saveTicker *time.Ticker
	quit       chan struct{}
}

type workloadProfile struct {
	Type      WorkloadType
	Metrics   map[string]*metricDistribution
	UpdatedAt time.Time
}

type metricDistribution struct {
	Name    string
	Count   int64
	Mean    float64
	StdDev  float64
	P50     float64
	P95     float64
	P99     float64
	Max     float64
	Samples []float64 // ring buffer (capacity 1000)
	Pos     int
}

// NewAdaptiveThresholdDB creates an adaptive threshold engine.
func NewAdaptiveThresholdDB(dataDir string) *AdaptiveThresholdDB {
	db := &AdaptiveThresholdDB{
		workloads: make(map[WorkloadType]*workloadProfile),
		dataDir:   dataDir,
		quit:      make(chan struct{}),
	}
	db.load()
	// Auto-save every 5 minutes
	db.saveTicker = time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-db.saveTicker.C:
				db.save()
			case <-db.quit:
				return
			}
		}
	}()
	return db
}

// Close stops the background save goroutine.
func (db *AdaptiveThresholdDB) Close() {
	close(db.quit)
	if db.saveTicker != nil {
		db.saveTicker.Stop()
	}
	db.save()
}

// Observe records a metric sample for the given workload type.
func (db *AdaptiveThresholdDB) Observe(wt WorkloadType, metricName string, value float64) {
	db.mu.Lock()
	defer db.mu.Unlock()

	prof, ok := db.workloads[wt]
	if !ok {
		prof = &workloadProfile{
			Type:    wt,
			Metrics: make(map[string]*metricDistribution),
		}
		db.workloads[wt] = prof
	}

	dist, ok := prof.Metrics[metricName]
	if !ok {
		dist = &metricDistribution{
			Name:    metricName,
			Samples: make([]float64, 1000),
		}
		prof.Metrics[metricName] = dist
	}

	dist.Count++
	if value > dist.Max {
		dist.Max = value
	}

	// Ring buffer
	dist.Samples[dist.Pos] = value
	dist.Pos = (dist.Pos + 1) % len(dist.Samples)

	// Recompute statistics from ring buffer every 10 samples
	if dist.Count%10 == 0 {
		dist.recompute()
	}
}

// Threshold returns the adaptive warn/crit thresholds for a metric.
// Falls back to baseWarn/baseCrit if insufficient data.
func (db *AdaptiveThresholdDB) Threshold(wt WorkloadType, metricName string, baseWarn, baseCrit float64) (warn, crit float64) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	prof, ok := db.workloads[wt]
	if !ok {
		return baseWarn, baseCrit
	}
	dist, ok := prof.Metrics[metricName]
	if !ok || dist.Count < 30 {
		return baseWarn, baseCrit
	}

	// Adaptive: warn at mean + 2σ, crit at mean + 3σ
	// But never lower than base thresholds (avoid false alarms during idle)
	warn = dist.Mean + 2*dist.StdDev
	crit = dist.Mean + 3*dist.StdDev
	if warn < baseWarn {
		warn = baseWarn
	}
	if crit < baseCrit {
		crit = baseCrit
	}
	return warn, crit
}

// DetectWorkloadType infers the workload type from running processes and apps.
func DetectWorkloadType(curr *model.Snapshot) WorkloadType {
	scores := make(map[WorkloadType]int)

	for _, app := range curr.Global.Apps.Instances {
		switch app.AppType {
		case "nginx", "apache", "caddy", "haproxy":
			scores[WorkloadWeb] += 3
		case "mysql", "mariadb", "postgresql", "mongodb":
			scores[WorkloadDatabase] += 3
		case "redis", "memcached":
			scores[WorkloadCache] += 3
		case "kafka", "rabbitmq":
			scores[WorkloadMessageQueue] += 3
		}
	}

	// Check process names
	for _, p := range curr.Processes {
		comm := strings.ToLower(p.Comm)
		switch {
		case strings.Contains(comm, "nginx") || strings.Contains(comm, "apache"):
			scores[WorkloadWeb]++
		case strings.Contains(comm, "mysql") || strings.Contains(comm, "postgres") || strings.Contains(comm, "mongod"):
			scores[WorkloadDatabase]++
		case strings.Contains(comm, "redis"):
			scores[WorkloadCache]++
		case strings.Contains(comm, "kubelet") || strings.Contains(comm, "containerd"):
			scores[WorkloadKubernetes] += 2
		case strings.Contains(comm, "java") && strings.Contains(comm, "spark"):
			scores[WorkloadBatch]++
		}
	}

	// Check cgroup names
	for _, id := range curr.Global.AppIdentities {
		if strings.Contains(id.CgroupPath, "kubepods") {
			scores[WorkloadKubernetes] += 2
		}
	}

	if len(scores) == 0 {
		return WorkloadUnknown
	}

	type kv struct {
		k WorkloadType
		v int
	}
	var sorted []kv
	for k, v := range scores {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	return sorted[0].k
}

// recompute calculates mean, stddev, and percentiles from the ring buffer.
func (d *metricDistribution) recompute() {
	var vals []float64
	for _, v := range d.Samples {
		if v != 0 || d.Count <= int64(len(d.Samples)) {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		return
	}

	sort.Float64s(vals)
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	d.Mean = sum / float64(len(vals))

	// StdDev
	var sqSum float64
	for _, v := range vals {
		diff := v - d.Mean
		sqSum += diff * diff
	}
	d.StdDev = math.Sqrt(sqSum / float64(len(vals)))

	d.P50 = adaptivePercentile(vals, 0.5)
	d.P95 = adaptivePercentile(vals, 0.95)
	d.P99 = adaptivePercentile(vals, 0.99)
}

func adaptivePercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ─── Persistence ────────────────────────────────────────────────────────────

const adaptiveDBFile = "adaptive-thresholds.json"

func (db *AdaptiveThresholdDB) save() {
	db.mu.RLock()
	defer db.mu.RUnlock()

	path := filepath.Join(db.dataDir, adaptiveDBFile)
	data, err := json.MarshalIndent(db.workloads, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0o600)
}

func (db *AdaptiveThresholdDB) load() {
	path := filepath.Join(db.dataDir, adaptiveDBFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var loaded map[WorkloadType]*workloadProfile
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	for k, v := range loaded {
		db.workloads[k] = v
	}
}

// AdaptiveThreshold returns adaptive thresholds for a metric, auto-detecting workload.
// This is the convenience function RCA detectors should call.
func AdaptiveThreshold(db *AdaptiveThresholdDB, curr *model.Snapshot, metricName string, baseWarn, baseCrit float64) (warn, crit float64) {
	if db == nil {
		return baseWarn, baseCrit
	}
	wt := DetectWorkloadType(curr)
	return db.Threshold(wt, metricName, baseWarn, baseCrit)
}
