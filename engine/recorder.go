package engine

import (
	"encoding/json"
	"io"
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

// Base returns the underlying engine.
func (r *Recorder) Base() *Engine {
	return r.inner
}

// Tick records a frame and returns it.
func (r *Recorder) Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	return r.RecordTick()
}

// RecordTick calls the engine's Tick and records the result.
func (r *Recorder) RecordTick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	return r.RecordTickWithProbe(nil)
}

// RecordTickWithProbe calls the engine's Tick and records the result along with probe findings.
func (r *Recorder) RecordTickWithProbe(probe *ProbeFindings) (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	snap, rates, result := r.inner.Tick()
	if snap != nil {
		r.mu.Lock()
		if err := r.writer.Encode(recordFrame{
			Snapshot: *snap,
			Rates:    rates,
			Result:   result,
			Probe:    probe,
		}); err != nil {
			// Log encode error but don't fail the tick
			_ = err
		}
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
	last   *recordFrame
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

	return p, nil
}

// Base returns the underlying engine.
func (p *Player) Base() *Engine {
	return p.Engine
}

// Tick replays the next recorded frame (or the last frame if at EOF).
func (p *Player) Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.frames) == 0 {
		return nil, nil, nil
	}

	if p.idx >= len(p.frames) {
		if p.last != nil {
			return &p.last.Snapshot, p.last.Rates, p.last.Result
		}
		f := &p.frames[len(p.frames)-1]
		return &f.Snapshot, f.Rates, f.Result
	}

	f := &p.frames[p.idx]
	p.idx++
	p.last = f

	// Feed history for trends
	p.Engine.History.Push(f.Snapshot)
	if f.Rates != nil {
		p.Engine.History.PushRate(*f.Rates)
	}

	return &f.Snapshot, f.Rates, f.Result
}

// Len returns the number of frames available.
func (p *Player) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.frames)
}

// Index returns the next frame index.
func (p *Player) Index() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.idx
}

// Seek jumps to a frame index and returns that frame.
func (p *Player) Seek(i int) (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.frames) == 0 {
		return nil, nil, nil
	}
	if i < 0 {
		i = 0
	}
	if i >= len(p.frames) {
		i = len(p.frames) - 1
	}
	p.idx = i
	f := &p.frames[p.idx]
	p.idx++
	p.last = f
	// Feed history for trends
	p.Engine.History.Push(f.Snapshot)
	if f.Rates != nil {
		p.Engine.History.PushRate(*f.Rates)
	}
	return &f.Snapshot, f.Rates, f.Result
}
