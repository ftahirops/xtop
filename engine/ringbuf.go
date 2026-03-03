package engine

import (
	"sync"
	"time"
)

// RingBuf is a generic ring buffer with thread-safe access.
type RingBuf[T any] struct {
	buf  []T
	head int
	size int
	cap  int
	mu   sync.RWMutex
}

// NewRingBuf creates a new ring buffer with the given capacity.
func NewRingBuf[T any](capacity int) *RingBuf[T] {
	return &RingBuf[T]{
		buf: make([]T, capacity),
		cap: capacity,
	}
}

// Push adds an element to the ring buffer.
func (r *RingBuf[T]) Push(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.head] = v
	r.head = (r.head + 1) % r.cap
	if r.size < r.cap {
		r.size++
	}
}

// Get returns the i-th element (0 = oldest).
func (r *RingBuf[T]) Get(i int) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var zero T
	if i < 0 || i >= r.size {
		return zero, false
	}
	idx := (r.head - r.size + i + r.cap) % r.cap
	return r.buf[idx], true
}

// Latest returns the most recently pushed element.
func (r *RingBuf[T]) Latest() (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var zero T
	if r.size == 0 {
		return zero, false
	}
	idx := (r.head - 1 + r.cap) % r.cap
	return r.buf[idx], true
}

// Len returns the number of elements in the buffer.
func (r *RingBuf[T]) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

// Slice returns all elements oldest-first.
func (r *RingBuf[T]) Slice() []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]T, r.size)
	for i := 0; i < r.size; i++ {
		idx := (r.head - r.size + i + r.cap) % r.cap
		out[i] = r.buf[idx]
	}
	return out
}

// TimeSeries1s is a 1-second resolution metric sample.
type TimeSeries1s struct {
	Timestamp time.Time
	Health    int     // HealthLevel as int
	Score     int
	CPUBusy   float64
	MemPct    float64
	IOPSI     float64
	TopPID    int
	TopComm   string
}

// TimeSeries10s is a 10-second resolution aggregate sample.
type TimeSeries10s struct {
	Timestamp time.Time
	HealthMax int     // worst health in window
	ScoreMax  int
	CPUMin    float64
	CPUMax    float64
	CPUAvg    float64
	MemMin    float64
	MemMax    float64
	MemAvg    float64
	IOPSIMax  float64
}

// MultiResBuffer holds multi-resolution time series data.
type MultiResBuffer struct {
	HiRes  *RingBuf[TimeSeries1s]  // cap=120, last 2 min
	MedRes *RingBuf[TimeSeries10s] // cap=2160, last 6h

	// Accumulator for downsampling
	accum    []TimeSeries1s
	accumMu  sync.Mutex
}

// NewMultiResBuffer creates a new multi-resolution buffer.
func NewMultiResBuffer() *MultiResBuffer {
	return &MultiResBuffer{
		HiRes:  NewRingBuf[TimeSeries1s](120),
		MedRes: NewRingBuf[TimeSeries10s](2160),
		accum:  make([]TimeSeries1s, 0, 10),
	}
}

// PushHiRes adds a 1-second sample and handles downsampling to 10s.
func (m *MultiResBuffer) PushHiRes(sample TimeSeries1s) {
	m.HiRes.Push(sample)

	m.accumMu.Lock()
	defer m.accumMu.Unlock()

	m.accum = append(m.accum, sample)
	if len(m.accum) >= 10 {
		m.MedRes.Push(downsample(m.accum))
		m.accum = m.accum[:0]
	}
}

// downsample computes a 10-second aggregate from 10 hi-res samples.
func downsample(samples []TimeSeries1s) TimeSeries10s {
	if len(samples) == 0 {
		return TimeSeries10s{}
	}

	ts := TimeSeries10s{
		Timestamp: samples[len(samples)-1].Timestamp,
		HealthMax: samples[0].Health,
		ScoreMax:  samples[0].Score,
		CPUMin:    samples[0].CPUBusy,
		CPUMax:    samples[0].CPUBusy,
		MemMin:    samples[0].MemPct,
		MemMax:    samples[0].MemPct,
	}

	var cpuSum, memSum float64
	for _, s := range samples {
		if s.Health > ts.HealthMax {
			ts.HealthMax = s.Health
		}
		if s.Score > ts.ScoreMax {
			ts.ScoreMax = s.Score
		}
		if s.CPUBusy < ts.CPUMin {
			ts.CPUMin = s.CPUBusy
		}
		if s.CPUBusy > ts.CPUMax {
			ts.CPUMax = s.CPUBusy
		}
		if s.MemPct < ts.MemMin {
			ts.MemMin = s.MemPct
		}
		if s.MemPct > ts.MemMax {
			ts.MemMax = s.MemPct
		}
		if s.IOPSI > ts.IOPSIMax {
			ts.IOPSIMax = s.IOPSI
		}
		cpuSum += s.CPUBusy
		memSum += s.MemPct
	}

	n := float64(len(samples))
	ts.CPUAvg = cpuSum / n
	ts.MemAvg = memSum / n
	return ts
}
