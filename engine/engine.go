package engine

import (
	"sync"
	"time"

	"github.com/ftahirops/xtop/collector"
	cgcollector "github.com/ftahirops/xtop/collector/cgroup"
	bpf "github.com/ftahirops/xtop/collector/ebpf"
	"github.com/ftahirops/xtop/collector/apps"
	rt "github.com/ftahirops/xtop/collector/runtime"
	"github.com/ftahirops/xtop/model"
)

// Engine orchestrates collection, analysis, and scoring.
type Engine struct {
	registry      *collector.Registry
	cgCollect     *cgcollector.Collector
	History       *History
	Smart         *collector.SMARTCollector
	growthTracker *MountGrowthTracker
	Sentinel      *bpf.SentinelManager
	Watchdog      *WatchdogTrigger
	SecWatchdog   *bpf.SecWatchdog // security deep-inspection watchdog
	MultiRes      *MultiResBuffer  // multi-resolution time series (nil if unused)
	SLOPolicies   []SLOPolicy     // SLO policies from config/flags
	Autopilot     *Autopilot      // autopilot subsystem (nil if disabled)
	tickMu        sync.Mutex      // serializes Tick() calls to prevent concurrent collection
}

// NewEngine creates a new engine with all collectors registered.
// intervalSec is the collection interval used to calibrate alert thresholds.
func NewEngine(historySize, intervalSec int) *Engine {
	reg := collector.NewRegistry()
	cgc := cgcollector.NewCollector()
	reg.Add(cgc)

	sentinel := bpf.NewSentinelManager()
	reg.Add(sentinel)

	// Runtime detection modules — runs after ProcessCollector so snap.Processes is available
	rtm := rt.NewManager()
	rtm.Register(rt.NewDotNetModule())
	rtm.Register(rt.NewJVMModule())
	rtm.Register(rt.NewPythonModule())
	rtm.Register(rt.NewNodeModule())
	rtm.Register(rt.NewGoModule())
	reg.Add(rtm)

	// App diagnostics — auto-detect and monitor running applications
	appm := apps.NewManager()
	appm.Register(apps.NewNginxModule())
	appm.Register(apps.NewApacheModule())
	appm.Register(apps.NewHAProxyModule())
	appm.Register(apps.NewCaddyModule())
	appm.Register(apps.NewTraefikModule())
	appm.Register(apps.NewMySQLModule())
	appm.Register(apps.NewPostgreSQLModule())
	appm.Register(apps.NewMongoModule())
	appm.Register(apps.NewRedisModule())
	appm.Register(apps.NewMemcachedModule())
	appm.Register(apps.NewESModule())
	appm.Register(apps.NewRabbitMQModule())
	appm.Register(apps.NewKafkaModule())
	appm.Register(apps.NewDockerModule())
	reg.Add(appm)

	return &Engine{
		registry:      reg,
		cgCollect:     cgc,
		History:       NewHistory(historySize, intervalSec),
		Smart:         collector.NewSMARTCollector(5 * time.Minute),
		growthTracker: NewMountGrowthTracker(),
		Sentinel:      sentinel,
		Watchdog:      NewWatchdogTrigger(),
		SecWatchdog:   bpf.NewSecWatchdog(bpf.DetectPrimaryIface()),
	}
}

// Tick performs one collection + analysis cycle.
// Returns the snapshot, computed rates, and full analysis result.
// Serialized via tickMu to prevent concurrent collection when ticks overlap.
func (e *Engine) Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	e.tickMu.Lock()
	defer e.tickMu.Unlock()

	snap := &model.Snapshot{
		Timestamp: time.Now(),
	}

	// Collect all metrics
	if errs := e.registry.CollectAll(snap); len(errs) > 0 {
		for _, err := range errs {
			if err != nil {
				snap.Errors = append(snap.Errors, err.Error())
			}
		}
	}

	// Collect security watchdog probe data into security metrics
	if e.SecWatchdog != nil {
		e.SecWatchdog.Collect(&snap.Global.Security)
	}

	// Get previous snapshot for rate calculations
	prev := e.History.Latest()

	// Store in history
	e.History.Push(*snap)

	// Compute rates and run analysis
	var rates *model.RateSnapshot
	var result *model.AnalysisResult

	if prev != nil {
		r := ComputeRates(prev, snap)
		e.growthTracker.Smooth(r.MountRates)
		rates = &r
		e.History.PushRate(r)
		result = AnalyzeRCA(snap, rates, e.History)

		// Watchdog auto-trigger: check if RCA warrants domain-specific probes
		if domain := e.Watchdog.Check(result); domain != "" {
			result.Watchdog = model.WatchdogState{Active: true, Domain: domain}
		}

		// Security watchdog: trigger deep inspection probes from evidence
		if e.SecWatchdog != nil {
			var allEvidence []model.Evidence
			for _, entry := range result.RCA {
				allEvidence = append(allEvidence, entry.EvidenceV2...)
			}
			e.SecWatchdog.TriggerFromEvidence(allEvidence)
		}

		// Trigger disk scanners when filesystem pressure detected
		worst := WorstDiskGuardState(r.MountRates)
		if worst == "WARN" || worst == "CRIT" {
			e.registry.TriggerByName("bigfiles")
			e.registry.TriggerByName("deleted_open")
		}

		// Push to multi-resolution buffer if enabled
		if e.MultiRes != nil {
			memPct := float64(0)
			if snap.Global.Memory.Total > 0 {
				memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
			}
			e.MultiRes.PushHiRes(TimeSeries1s{
				Timestamp: snap.Timestamp,
				Health:    int(result.Health),
				Score:     result.PrimaryScore,
				CPUBusy:   rates.CPUBusyPct,
				MemPct:    memPct,
				IOPSI:     snap.Global.PSI.IO.Full.Avg10,
				TopPID:    result.PrimaryPID,
				TopComm:   primaryDisplayName(result),
			})
		}
	}

	return snap, rates, result
}

// Close shuts down all engine resources (sentinel probes, security watchdog).
func (e *Engine) Close() {
	if e.Sentinel != nil {
		e.Sentinel.Close()
	}
	if e.SecWatchdog != nil {
		e.SecWatchdog.Close()
	}
}

// primaryDisplayName returns the best display name for the primary culprit.
func primaryDisplayName(result *model.AnalysisResult) string {
	if result.PrimaryAppName != "" {
		return result.PrimaryAppName
	}
	return result.PrimaryProcess
}
