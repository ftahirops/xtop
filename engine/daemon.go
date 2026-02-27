package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/model"
)

// DaemonConfig holds daemon-specific configuration.
type DaemonConfig struct {
	DataDir  string
	Interval time.Duration
	History  int
	Metrics  *MetricsStore
	Alerts   AlertConfig
}

// compactSummary is a minimal per-tick record for the rolling log.
type compactSummary struct {
	Timestamp  time.Time `json:"ts"`
	Health     string    `json:"health"`
	Score      int       `json:"score"`
	Bottleneck string    `json:"bottleneck,omitempty"`
	CPUBusy    float64   `json:"cpu_busy"`
	MemUsedPct float64   `json:"mem_pct"`
	CPUPSISome float64   `json:"cpu_psi"`
	MemPSIFull float64   `json:"mem_psi"`
	IOPSIFull  float64   `json:"io_psi"`
	DiskState  string    `json:"disk_state"`
	NetState   string    `json:"net_state"`
	// RCA fields for smart shell widget
	Culprit        string `json:"culprit,omitempty"`
	Process        string `json:"process,omitempty"`
	ProcessPID     int    `json:"pid,omitempty"`
	CausalChain    string `json:"chain,omitempty"`
	HiddenLatency  bool   `json:"hidden_latency,omitempty"`
	HiddenDesc     string `json:"hidden_desc,omitempty"`
	RecentDeploy   string `json:"recent_deploy,omitempty"`
	DeployAge      int    `json:"deploy_age,omitempty"`
}

// RunDaemon runs xtop as a background collector, writing events to DataDir.
func RunDaemon(cfg DaemonConfig) error {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Write PID file
	pidPath := filepath.Join(cfg.DataDir, "daemon.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	defer os.Remove(pidPath)

	eng := NewEngine(cfg.History, int(cfg.Interval.Seconds()))
	engTicker := Ticker(eng)
	if cfg.Metrics != nil {
		engTicker = NewInstrumentedTicker(engTicker, cfg.Metrics)
	}
	detector := NewEventDetector()
	notifier := NewNotifier(cfg.Alerts)
	eventWriter := NewEventLogWriter(filepath.Join(cfg.DataDir, "events.jsonl"))
	summaryPath := filepath.Join(cfg.DataDir, "current.jsonl")

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	intervalTicker := time.NewTicker(cfg.Interval)
	defer intervalTicker.Stop()

	log.Printf("xtop daemon started (pid=%d, interval=%s, datadir=%s)", os.Getpid(), cfg.Interval, cfg.DataDir)

	prevCompleted := 0
	prevHealth := model.HealthOK
	incidentDir := filepath.Join(cfg.DataDir, "incidents")
	if err := os.MkdirAll(incidentDir, 0700); err != nil {
		log.Printf("create incident dir: %v", err)
	}

	for {
		select {
		case <-sigCh:
			log.Printf("xtop daemon shutting down")
			return nil
		case <-intervalTicker.C:
			snap, rates, result := engTicker.Tick()
			if snap == nil || result == nil {
				continue
			}

			// Event detection
			detector.Process(snap, rates, result)

			// Auto-snapshot on health transition to CRITICAL
			if result.Health == model.HealthCritical && prevHealth != model.HealthCritical {
				snapPath := filepath.Join(incidentDir,
					fmt.Sprintf("incident-%s.json", snap.Timestamp.Format("2006-01-02T15-04-05")))
				saveIncidentSnapshot(snapPath, snap, rates, result)
				log.Printf("AUTO-SNAPSHOT: %s (bottleneck=%s, score=%d)",
					snapPath, result.PrimaryBottleneck, result.PrimaryScore)
				if notifier.Enabled() {
					notifier.Notify("health_critical", map[string]interface{}{
						"bottleneck": result.PrimaryBottleneck,
						"score":      result.PrimaryScore,
						"culprit":    result.PrimaryCulprit,
						"process":    result.PrimaryProcess,
						"pid":        result.PrimaryPID,
					})
				}
			}
			if result.Health == model.HealthOK && prevHealth != model.HealthOK {
				if notifier.Enabled() {
					notifier.Notify("health_ok", map[string]interface{}{
						"stable_since": result.StableSince,
					})
				}
			}
			prevHealth = result.Health

			// Check for newly completed events
			// completed is reverse-chronological (newest first).
			_, completed := detector.AllEvents()
			if len(completed) > prevCompleted {
				// New events are at indices 0..newCount-1 (newest first).
				// Process oldest-first for chronological logging.
				newCount := len(completed) - prevCompleted
				for i := newCount - 1; i >= 0; i-- {
					evt := completed[i]
					if err := eventWriter.Write(evt); err != nil {
						log.Printf("error writing event: %v", err)
					} else {
						log.Printf("EVENT CLOSED: %s %s score=%d duration=%ds culprit=%s",
							evt.ID, evt.Bottleneck, evt.PeakScore, evt.Duration, evt.CulpritProcess)
						if notifier.Enabled() {
							notifier.Notify("event_closed", evt)
						}
					}
				}
				prevCompleted = len(completed)
			}

			// Write compact summary
			memPct := float64(0)
			if snap.Global.Memory.Total > 0 {
				memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
			}
			cpuBusy := float64(0)
			if rates != nil {
				cpuBusy = rates.CPUBusyPct
			}

			diskState := result.DiskGuardWorst
			if diskState == "" {
				diskState = "OK"
			}
			netState := NetHealthLevel(snap, rates)

			summary := compactSummary{
				Timestamp:      snap.Timestamp,
				Health:         result.Health.String(),
				Score:          result.PrimaryScore,
				Bottleneck:     result.PrimaryBottleneck,
				CPUBusy:        cpuBusy,
				MemUsedPct:     memPct,
				CPUPSISome:     snap.Global.PSI.CPU.Some.Avg10,
				MemPSIFull:     snap.Global.PSI.Memory.Full.Avg10,
				IOPSIFull:      snap.Global.PSI.IO.Full.Avg10,
				DiskState:      diskState,
				NetState:       netState,
				Culprit:        result.PrimaryCulprit,
				Process:        result.PrimaryProcess,
				ProcessPID:     result.PrimaryPID,
				CausalChain:    result.CausalChain,
				HiddenLatency:  result.HiddenLatency,
				HiddenDesc:     result.HiddenLatencyDesc,
				RecentDeploy:   result.RecentDeploy,
				DeployAge:      result.RecentDeployAge,
			}
			writeSummaryLine(summaryPath, summary)
		}
	}
}

// saveIncidentSnapshot writes a full snapshot to a JSON file on health transitions.
func saveIncidentSnapshot(path string, snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	type incidentSnapshot struct {
		Timestamp  time.Time            `json:"timestamp"`
		Health     string               `json:"health"`
		Score      int                  `json:"score"`
		Bottleneck string               `json:"bottleneck"`
		Culprit    string               `json:"culprit,omitempty"`
		Process    string               `json:"process,omitempty"`
		PID        int                  `json:"pid,omitempty"`
		Evidence   []string             `json:"evidence,omitempty"`
		Chain      string               `json:"causal_chain,omitempty"`
		Actions    []model.Action       `json:"actions,omitempty"`
		Changes    []model.MetricChange `json:"top_changes,omitempty"`
		CPUBusy    float64              `json:"cpu_busy_pct"`
		MemUsedPct float64              `json:"mem_used_pct"`
		IOPSI      float64              `json:"io_psi_full"`
	}

	memPct := float64(0)
	if snap.Global.Memory.Total > 0 {
		memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
	}
	cpuBusy := float64(0)
	if rates != nil {
		cpuBusy = rates.CPUBusyPct
	}

	is := incidentSnapshot{
		Timestamp:  snap.Timestamp,
		Health:     result.Health.String(),
		Score:      result.PrimaryScore,
		Bottleneck: result.PrimaryBottleneck,
		Culprit:    result.PrimaryCulprit,
		Process:    result.PrimaryProcess,
		PID:        result.PrimaryPID,
		Evidence:   result.PrimaryEvidence,
		Chain:      result.CausalChain,
		Actions:    result.Actions,
		Changes:    result.TopChanges,
		CPUBusy:    cpuBusy,
		MemUsedPct: memPct,
		IOPSI:      snap.Global.PSI.IO.Full.Avg10,
	}

	data, err := json.MarshalIndent(is, "", "  ")
	if err != nil {
		log.Printf("marshal incident snapshot: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("write incident snapshot: %v", err)
	}
}

// writeSummaryLine appends a compact JSON line to the summary file.
// Rotates at 10MB.
func writeSummaryLine(path string, s compactSummary) {
	// Check file size for rotation
	if info, err := os.Stat(path); err == nil && info.Size() > 10*1024*1024 {
		// Rotate: rename to .old, start fresh
		_ = os.Rename(path, path+".old")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(s)
}
