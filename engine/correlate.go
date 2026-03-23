package engine

import (
	"math"
	"sync"
)

// decayLambda is the exponential decay factor applied per sample.
// At 0.98, the effective window is ~50 samples (~2.5 min at 3s interval).
const decayLambda = 0.98

// lagBufSize is the ring buffer size for cross-correlation lag detection.
const lagBufSize = 30

// maxLag is the maximum lag offset (in samples) to search for cross-correlation.
const maxLag = 10

// pairStats tracks streaming Pearson correlation between two metrics
// with exponential decay to emphasize recent observations.
type pairStats struct {
	N                    float64
	SumX, SumY          float64
	SumXX, SumYY, SumXY float64

	// Lag detection ring buffers
	xBuf    [lagBufSize]float64
	yBuf    [lagBufSize]float64
	bufPos  int
	bufFull bool
}

func (p *pairStats) add(x, y float64) {
	// Apply exponential decay to existing sums
	p.N *= decayLambda
	p.SumX *= decayLambda
	p.SumY *= decayLambda
	p.SumXX *= decayLambda
	p.SumYY *= decayLambda
	p.SumXY *= decayLambda

	// Accumulate new observation
	p.N += 1
	p.SumX += x
	p.SumY += y
	p.SumXX += x * x
	p.SumYY += y * y
	p.SumXY += x * y

	// Update lag ring buffers
	p.xBuf[p.bufPos] = x
	p.yBuf[p.bufPos] = y
	p.bufPos = (p.bufPos + 1) % lagBufSize
	if !p.bufFull && p.bufPos == 0 {
		p.bufFull = true
	}
}

func (p *pairStats) r() float64 {
	if p.N < 10 {
		return 0
	}
	n := p.N
	num := n*p.SumXY - p.SumX*p.SumY
	denX := n*p.SumXX - p.SumX*p.SumX
	denY := n*p.SumYY - p.SumY*p.SumY
	if denX <= 0 || denY <= 0 {
		return 0
	}
	return num / math.Sqrt(denX*denY)
}

// samples returns the effective number of samples (accounting for decay).
func (p *pairStats) samples() int64 {
	return int64(math.Round(p.N))
}

// BestLag returns the lag (in samples) that maximizes cross-correlation,
// and the correlation value at that lag. Positive lag means X leads Y.
func (p *pairStats) BestLag() (lag int, r float64) {
	if !p.bufFull {
		return 0, 0
	}
	bestLag, bestR := 0, 0.0
	for l := -maxLag; l <= maxLag; l++ {
		cr := crossCorrelationAtLag(p.xBuf[:], p.yBuf[:], p.bufPos, l)
		if math.Abs(cr) > math.Abs(bestR) {
			bestR = cr
			bestLag = l
		}
	}
	return bestLag, bestR
}

// crossCorrelationAtLag computes Pearson R between x and y shifted by lag positions
// in ring buffers of size lagBufSize with the write head at pos.
// Positive lag means x[t] is compared with y[t+lag] (x leads y).
func crossCorrelationAtLag(x, y []float64, pos, lag int) float64 {
	n := lagBufSize - absInt(lag)
	if n < 5 {
		return 0
	}

	var sumX, sumY, sumXX, sumYY, sumXY float64
	for i := 0; i < n; i++ {
		var xi, yi int
		if lag >= 0 {
			xi = (pos - lagBufSize + i + lagBufSize) % lagBufSize
			yi = (pos - lagBufSize + i + lag + lagBufSize) % lagBufSize
		} else {
			xi = (pos - lagBufSize + i - lag + lagBufSize) % lagBufSize
			yi = (pos - lagBufSize + i + lagBufSize) % lagBufSize
		}
		xv := x[xi]
		yv := y[yi]
		sumX += xv
		sumY += yv
		sumXX += xv * xv
		sumYY += yv * yv
		sumXY += xv * yv
	}

	fn := float64(n)
	num := fn*sumXY - sumX*sumY
	denX := fn*sumXX - sumX*sumX
	denY := fn*sumYY - sumY*sumY
	if denX <= 0 || denY <= 0 {
		return 0
	}
	return num / math.Sqrt(denX*denY)
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
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

// Samples returns how many effective observations exist for a pair.
func (c *Correlator) Samples(idA, idB string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		return 0
	}
	return p.samples()
}

// BestLag returns the lag (in samples) that maximizes cross-correlation
// for a given pair, along with the correlation at that lag.
// Positive lag means idA leads idB.
func (c *Correlator) BestLag(idA, idB string) (lag int, r float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		return 0, 0
	}
	l, cr := p.BestLag()
	// If the pair was stored with swapped order, flip the lag sign
	if idA > idB {
		l = -l
	}
	return l, cr
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
		if !ok || p.samples() < 30 {
			continue
		}
		r := p.r()
		if math.Abs(r) >= minR {
			results = append(results, result{A: pair[0], B: pair[1], R: r, N: p.samples()})
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
