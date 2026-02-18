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
)

// DaemonConfig holds daemon-specific configuration.
type DaemonConfig struct {
	DataDir  string
	Interval time.Duration
	History  int
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
}

// RunDaemon runs xtop as a background collector, writing events to DataDir.
func RunDaemon(cfg DaemonConfig) error {
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Write PID file
	pidPath := filepath.Join(cfg.DataDir, "daemon.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	defer os.Remove(pidPath)

	eng := NewEngine(cfg.History)
	detector := NewEventDetector()
	eventWriter := NewEventLogWriter(filepath.Join(cfg.DataDir, "events.jsonl"))
	summaryPath := filepath.Join(cfg.DataDir, "current.jsonl")

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	log.Printf("xtop daemon started (pid=%d, interval=%s, datadir=%s)", os.Getpid(), cfg.Interval, cfg.DataDir)

	prevCompleted := 0

	for {
		select {
		case <-sigCh:
			log.Printf("xtop daemon shutting down")
			return nil
		case <-ticker.C:
			snap, rates, result := eng.Tick()
			if snap == nil || result == nil {
				continue
			}

			// Event detection
			detector.Process(snap, rates, result)

			// Check for newly completed events
			_, completed := detector.AllEvents()
			if len(completed) > prevCompleted {
				for i := prevCompleted; i < len(completed); i++ {
					// completed is reverse-chronological, so newest is first
					// but prevCompleted tracks the total count
					evt := completed[len(completed)-1-i]
					if err := eventWriter.Write(evt); err != nil {
						log.Printf("error writing event: %v", err)
					} else {
						log.Printf("EVENT CLOSED: %s %s score=%d duration=%ds culprit=%s",
							evt.ID, evt.Bottleneck, evt.PeakScore, evt.Duration, evt.CulpritProcess)
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

			summary := compactSummary{
				Timestamp:  snap.Timestamp,
				Health:     result.Health.String(),
				Score:      result.PrimaryScore,
				Bottleneck: result.PrimaryBottleneck,
				CPUBusy:    cpuBusy,
				MemUsedPct: memPct,
				CPUPSISome: snap.Global.PSI.CPU.Some.Avg10,
				MemPSIFull: snap.Global.PSI.Memory.Full.Avg10,
				IOPSIFull:  snap.Global.PSI.IO.Full.Avg10,
			}
			writeSummaryLine(summaryPath, summary)
		}
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

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(s)
}
