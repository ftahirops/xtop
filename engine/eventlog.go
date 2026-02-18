package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// EventDetector tracks health state transitions and emits events.
type EventDetector struct {
	mu sync.Mutex

	active    *model.Event
	completed []model.Event

	// Debounce: require consecutive non-OK ticks before opening
	nonOKStreak int
	debounce    int // consecutive non-OK ticks required (default 3)
}

// NewEventDetector creates a new detector with default debounce of 3 ticks.
func NewEventDetector() *EventDetector {
	return &EventDetector{debounce: 3}
}

// Process is called every tick with the current analysis result.
// It detects health transitions and manages events.
func (d *EventDetector) Process(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	if result == nil || snap == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	isOK := result.Health == model.HealthOK
	now := snap.Timestamp

	if !isOK {
		d.nonOKStreak++
	} else {
		d.nonOKStreak = 0
	}

	if d.active != nil {
		if isOK {
			// Close the active event
			d.active.Active = false
			d.active.EndTime = now
			d.active.Duration = int(now.Sub(d.active.StartTime).Seconds())
			d.completed = append(d.completed, *d.active)
			d.active = nil
		} else {
			// Update peak metrics
			d.updatePeaks(snap, rates, result)
		}
		return
	}

	// No active event — check if we should open one
	if !isOK && d.nonOKStreak >= d.debounce {
		// Open new event
		d.active = &model.Event{
			ID:         fmt.Sprintf("evt-%d", now.UnixMilli()),
			StartTime:  now.Add(-time.Duration(d.debounce-1) * time.Second),
			PeakHealth: result.Health,
			Bottleneck: result.PrimaryBottleneck,
			PeakScore:  result.PrimaryScore,
			Active:     true,
		}
		d.updatePeaks(snap, rates, result)
	}
}

func (d *EventDetector) updatePeaks(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	if d.active == nil {
		return
	}

	if result.Health > d.active.PeakHealth {
		d.active.PeakHealth = result.Health
	}
	if result.PrimaryScore > d.active.PeakScore {
		d.active.PeakScore = result.PrimaryScore
		d.active.Bottleneck = result.PrimaryBottleneck
	}

	// Update evidence and chain from latest
	if len(result.PrimaryEvidence) > 0 {
		d.active.Evidence = result.PrimaryEvidence
	}
	if result.CausalChain != "" {
		d.active.CausalChain = result.CausalChain
	}
	if result.PrimaryCulprit != "" {
		d.active.CulpritCgroup = result.PrimaryCulprit
	}
	if result.PrimaryProcess != "" {
		d.active.CulpritProcess = result.PrimaryProcess
	}
	if result.PrimaryPID > 0 {
		d.active.CulpritPID = result.PrimaryPID
	}

	// Peak CPU
	if rates != nil && rates.CPUBusyPct > d.active.PeakCPUBusy {
		d.active.PeakCPUBusy = rates.CPUBusyPct
	}

	// Peak memory used %
	if snap.Global.Memory.Total > 0 {
		memPct := float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
		if memPct > d.active.PeakMemUsedPct {
			d.active.PeakMemUsedPct = memPct
		}
	}

	// Peak IO PSI
	ioPSI := snap.Global.PSI.IO.Full.Avg10
	if ioPSI > d.active.PeakIOPSI {
		d.active.PeakIOPSI = ioPSI
	}
}

// ActiveEvent returns a copy of the current active event, or nil.
func (d *EventDetector) ActiveEvent() *model.Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active == nil {
		return nil
	}
	cpy := *d.active
	return &cpy
}

// Events returns completed events in reverse chronological order.
func (d *EventDetector) Events() []model.Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Return reversed copy
	out := make([]model.Event, len(d.completed))
	for i, e := range d.completed {
		out[len(d.completed)-1-i] = e
	}
	return out
}

// AllEvents returns active (if any) + completed events for display.
func (d *EventDetector) AllEvents() (active *model.Event, completed []model.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	completed = make([]model.Event, len(d.completed))
	for i, e := range d.completed {
		completed[len(d.completed)-1-i] = e
	}
	return d.active, completed
}

// LoadEvents adds externally loaded events (e.g., from daemon log).
func (d *EventDetector) LoadEvents(events []model.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.completed = append(events, d.completed...)
}

// EventLogWriter appends events to a JSONL file.
type EventLogWriter struct {
	path string
	mu   sync.Mutex
}

// NewEventLogWriter creates a writer for the given path.
func NewEventLogWriter(path string) *EventLogWriter {
	return &EventLogWriter{path: path}
}

// Write appends an event to the log file.
func (w *EventLogWriter) Write(e model.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(e)
}

// ReadEventLog reads all events from a JSONL file.
func ReadEventLog(path string) ([]model.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []model.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line limit
	for scanner.Scan() {
		var e model.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue // skip malformed lines
		}
		events = append(events, e)
	}
	return events, scanner.Err()
}
