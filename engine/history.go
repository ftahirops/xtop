package engine

import (
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
}

// NewHistory creates a ring buffer with the given capacity.
func NewHistory(capacity int) *History {
	return &History{
		buf:     make([]model.Snapshot, capacity),
		rateBuf: make([]model.RateSnapshot, capacity),
		cap:     capacity,
		anomaly: &AnomalyState{},
	}
}

// Push adds a snapshot to the ring buffer.
func (h *History) Push(snap model.Snapshot) {
	h.buf[h.head] = snap
	h.head = (h.head + 1) % h.cap
	if h.size < h.cap {
		h.size++
	}
}

// PushRate stores a rate snapshot at the same position as the latest Push.
func (h *History) PushRate(rate model.RateSnapshot) {
	// Rate corresponds to the most recently pushed snapshot
	idx := (h.head - 1 + h.cap) % h.cap
	h.rateBuf[idx] = rate
}

// Len returns the number of snapshots stored.
func (h *History) Len() int {
	return h.size
}

// Latest returns the most recent snapshot.
func (h *History) Latest() *model.Snapshot {
	if h.size == 0 {
		return nil
	}
	idx := (h.head - 1 + h.cap) % h.cap
	return &h.buf[idx]
}

// Previous returns the snapshot before the most recent one.
func (h *History) Previous() *model.Snapshot {
	if h.size < 2 {
		return nil
	}
	idx := (h.head - 2 + h.cap) % h.cap
	return &h.buf[idx]
}

// Get returns the snapshot at position i (0 = oldest in buffer).
func (h *History) Get(i int) *model.Snapshot {
	if i < 0 || i >= h.size {
		return nil
	}
	idx := (h.head - h.size + i + h.cap) % h.cap
	return &h.buf[idx]
}

// GetRate returns the rate snapshot at position i (0 = oldest in buffer).
func (h *History) GetRate(i int) *model.RateSnapshot {
	if i < 0 || i >= h.size {
		return nil
	}
	idx := (h.head - h.size + i + h.cap) % h.cap
	r := &h.rateBuf[idx]
	if r.DeltaSec == 0 {
		return nil // no rate computed for this position
	}
	return r
}
