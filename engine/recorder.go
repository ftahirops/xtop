package engine

import (
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/ftahirops/xtop/model"
)

// recordFrame is one snapshot frame written to disk.
type recordFrame struct {
	Snapshot model.Snapshot        `json:"snapshot"`
	Rates    *model.RateSnapshot   `json:"rates,omitempty"`
	Result   *model.AnalysisResult `json:"result,omitempty"`
	Probe    *ProbeFindings        `json:"probe,omitempty"`
}

// Recorder wraps an engine and records every tick to a file.
type Recorder struct {
	Engine *Engine
	inner  *Engine
	writer *json.Encoder
	mu     sync.Mutex
	f      *os.File
}

// NewRecorder creates a recorder that writes JSON lines to w.
func NewRecorder(eng *Engine, w io.Writer) *Recorder {
	return &Recorder{
		Engine: eng,
		inner:  eng,
		writer: json.NewEncoder(w),
	}
}

// Close flushes and closes the recorder.
func (r *Recorder) Close() {
	// nothing special needed since we flush per write
}

// RecordTick calls the engine's Tick and records the result.
func (r *Recorder) RecordTick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	snap, rates, result := r.inner.Tick()
	if snap != nil {
		r.mu.Lock()
		r.writer.Encode(recordFrame{
			Snapshot: *snap,
			Rates:    rates,
			Result:   result,
		})
		r.mu.Unlock()
	}
	return snap, rates, result
}

// Player replays recorded frames through a virtual engine.
type Player struct {
	Engine *Engine
	frames []recordFrame
	idx    int
	mu     sync.Mutex
}

// NewPlayer creates a player from a recorded file (JSON lines).
func NewPlayer(r io.Reader, historySize int) (*Player, error) {
	dec := json.NewDecoder(r)
	var frames []recordFrame
	for {
		var frame recordFrame
		if err := dec.Decode(&frame); err != nil {
			if err == io.EOF {
				break
			}
			// Try to continue past malformed lines
			continue
		}
		frames = append(frames, frame)
	}

	eng := NewEngine(historySize)

	p := &Player{
		Engine: eng,
		frames: frames,
	}

	// Override the engine's Tick to replay frames
	// We do this by pre-loading history
	for _, f := range frames {
		eng.History.Push(f.Snapshot)
	}

	return p, nil
}
