package engine

import (
	"sync"

	"github.com/ftahirops/xtop/model"
)

// History is a ring buffer of snapshots and rates for trend detection.
type History struct {
	buf     []model.Snapshot
	rateBuf []model.RateSnapshot
	head    int
	size    int
	cap     int
	anomaly *AnomalyState
	alert   *AlertState
	mu      sync.RWMutex
}

// NewHistory creates a ring buffer with the given capacity.
func NewHistory(capacity int) *History {
	return &History{
		buf:     make([]model.Snapshot, capacity),
		rateBuf: make([]model.RateSnapshot, capacity),
		cap:     capacity,
		anomaly: &AnomalyState{},
		alert:   &AlertState{},
	}
}

// Push adds a snapshot to the ring buffer.
func (h *History) Push(snap model.Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf[h.head] = snap
	h.head = (h.head + 1) % h.cap
	if h.size < h.cap {
		h.size++
	}
}

// PushRate stores a rate snapshot at the same position as the latest Push.
func (h *History) PushRate(rate model.RateSnapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Rate corresponds to the most recently pushed snapshot
	idx := (h.head - 1 + h.cap) % h.cap
	h.rateBuf[idx] = rate
}

// Len returns the number of snapshots stored.
func (h *History) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.size
}

// Latest returns a copy of the most recent snapshot.
func (h *History) Latest() *model.Snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.size == 0 {
		return nil
	}
	idx := (h.head - 1 + h.cap) % h.cap
	snap := h.buf[idx] // copy
	return &snap
}

// Previous returns a copy of the snapshot before the most recent one.
func (h *History) Previous() *model.Snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.size < 2 {
		return nil
	}
	idx := (h.head - 2 + h.cap) % h.cap
	snap := h.buf[idx] // copy
	return &snap
}

// Get returns a copy of the snapshot at position i (0 = oldest in buffer).
func (h *History) Get(i int) *model.Snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if i < 0 || i >= h.size {
		return nil
	}
	idx := (h.head - h.size + i + h.cap) % h.cap
	snap := h.buf[idx] // copy
	return &snap
}

// GetRate returns a copy of the rate snapshot at position i (0 = oldest in buffer).
func (h *History) GetRate(i int) *model.RateSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if i < 0 || i >= h.size {
		return nil
	}
	idx := (h.head - h.size + i + h.cap) % h.cap
	r := h.rateBuf[idx] // copy
	if r.DeltaSec == 0 {
		return nil // no rate computed for this position
	}
	return &r
}
