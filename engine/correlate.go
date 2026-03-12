package engine

import (
	"math"
	"sync"
)

// pairStats tracks streaming Pearson correlation between two metrics.
type pairStats struct {
	N                   int64
	SumX, SumY         float64
	SumXX, SumYY, SumXY float64
}

func (p *pairStats) add(x, y float64) {
	p.N++
	p.SumX += x
	p.SumY += y
	p.SumXX += x * x
	p.SumYY += y * y
	p.SumXY += x * y
}

func (p *pairStats) r() float64 {
	if p.N < 10 {
		return 0
	}
	n := float64(p.N)
	num := n*p.SumXY - p.SumX*p.SumY
	denX := n*p.SumXX - p.SumX*p.SumX
	denY := n*p.SumYY - p.SumY*p.SumY
	if denX <= 0 || denY <= 0 {
		return 0
	}
	return num / math.Sqrt(denX*denY)
}

// pairKey generates a canonical key for a metric pair (sorted order).
func pairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// Correlator tracks streaming Pearson correlations for pre-defined metric pairs.
type Correlator struct {
	mu    sync.RWMutex
	pairs map[string]*pairStats
}

// NewCorrelator creates a new streaming correlation tracker.
func NewCorrelator() *Correlator {
	return &Correlator{
		pairs: make(map[string]*pairStats),
	}
}

// Add feeds a paired observation for two metrics.
func (c *Correlator) Add(idA, idB string, valA, valB float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		p = &pairStats{}
		c.pairs[key] = p
	}
	if idA > idB {
		valA, valB = valB, valA
	}
	p.add(valA, valB)
}

// R returns the Pearson correlation coefficient for a pair.
// Returns 0 if insufficient data.
func (c *Correlator) R(idA, idB string) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		return 0
	}
	return p.r()
}

// Samples returns how many observations exist for a pair.
func (c *Correlator) Samples(idA, idB string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		return 0
	}
	return p.N
}

// correlationPairs defines which metric pairs to track correlation for.
var correlationPairs = [][2]string{
	{"cpu.busy", "cpu.runqueue"},
	{"cpu.busy", "io.disk.latency"},
	{"cpu.runqueue", "io.disk.latency"},
	{"mem.reclaim.direct", "io.disk.latency"},
	{"mem.swap.in", "io.disk.latency"},
	{"mem.available.low", "mem.psi"},
	{"mem.psi", "io.psi"},
	{"cpu.psi", "cpu.runqueue"},
	{"cpu.iowait", "io.disk.latency"},
	{"cpu.iowait", "io.psi"},
	{"net.tcp.retrans", "net.drops"},
	{"net.conntrack", "net.drops"},
	{"net.tcp.timewait", "net.ephemeral"},
	{"net.drops.rx", "net.tcp.retrans"},
	{"cpu.steal", "cpu.psi"},
	{"io.disk.util", "io.disk.latency"},
	{"io.disk.queuedepth", "io.disk.latency"},
	{"mem.psi.acceleration", "mem.reclaim.direct"},
	{"mem.slab.leak", "mem.available.low"},
	{"cpu.irq.imbalance", "net.drops"},
}

// UpdateFromEvidence feeds current tick's evidence values into all tracked correlation pairs.
func (c *Correlator) UpdateFromEvidence(evidenceMap map[string]float64) {
	for _, pair := range correlationPairs {
		valA, okA := evidenceMap[pair[0]]
		valB, okB := evidenceMap[pair[1]]
		if okA && okB {
			c.Add(pair[0], pair[1], valA, valB)
		}
	}
}

// TopCorrelations returns the pairs with |R| > minR, sorted by |R| descending.
func (c *Correlator) TopCorrelations(minR float64, maxN int) []struct {
	A, B string
	R    float64
	N    int64
} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	type result = struct {
		A, B string
		R    float64
		N    int64
	}
	var results []result
	for _, pair := range correlationPairs {
		key := pairKey(pair[0], pair[1])
		p, ok := c.pairs[key]
		if !ok || p.N < 30 {
			continue
		}
		r := p.r()
		if math.Abs(r) >= minR {
			results = append(results, result{A: pair[0], B: pair[1], R: r, N: p.N})
		}
	}

	// Sort by |R| descending
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if math.Abs(results[j].R) > math.Abs(results[i].R) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	if len(results) > maxN {
		results = results[:maxN]
	}
	return results
}
