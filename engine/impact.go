package engine

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// Impact weights for composite score calculation.
const (
	weightCPU = 0.30
	weightPSI = 0.20
	weightIO  = 0.20
	weightMem = 0.20
	weightNet = 0.10

	newnessBonus   = 0.15
	newnessAgeSec  = 60
	impactMaxProcs = 100
)

// ComputeImpactScores calculates a composite impact score for each process.
// Weights: CPU=0.30, PSI=0.20, IO=0.20, Mem=0.20, Net=0.10.
// Newness penalty: +0.15 for processes started <60s ago.
func ComputeImpactScores(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) []model.ImpactScore {
	if rates == nil || len(rates.ProcessRates) == 0 {
		return nil
	}

	// Find max values for normalization
	var maxCPU, maxMem, maxIO float64
	for _, p := range rates.ProcessRates {
		if p.CPUPct > maxCPU {
			maxCPU = p.CPUPct
		}
		if p.MemPct > maxMem {
			maxMem = p.MemPct
		}
		totalIO := p.ReadMBs + p.WriteMBs
		if totalIO > maxIO {
			maxIO = totalIO
		}
	}
	maxNet := rates.RetransRate
	if maxNet < 1 {
		maxNet = 1
	}

	// PSI pressure for weighting per-process contribution
	psiLoad := snap.Global.PSI.CPU.Some.Avg10 +
		snap.Global.PSI.Memory.Some.Avg10 +
		snap.Global.PSI.IO.Some.Avg10
	maxPSI := maxCPU

	// Boot time for newness detection
	now := time.Now()
	bootTime := readBootTime()

	scores := make([]model.ImpactScore, 0, len(rates.ProcessRates))
	for _, p := range rates.ProcessRates {
		if isKernelThread(p.Comm) {
			continue
		}
		if p.CPUPct < 0.1 && p.MemPct < 0.1 {
			continue
		}

		cpuNorm := normRatio(p.CPUPct, maxCPU)
		memNorm := normRatio(p.MemPct, maxMem)
		ioNorm := normRatio(p.ReadMBs+p.WriteMBs, maxIO)
		netNorm := float64(0) // network impact per process is hard; use retrans as proxy
		// PSI contribution: process CPU share * system PSI pressure
		psiNorm := float64(0)
		if psiLoad > 0 && maxPSI > 0 {
			psiNorm = normRatio(p.CPUPct, maxPSI) * clamp01(psiLoad/100)
		}

		composite := cpuNorm*weightCPU + psiNorm*weightPSI + ioNorm*weightIO +
			memNorm*weightMem + netNorm*weightNet

		// Newness penalty: boost for recently started processes
		newness := float64(0)
		if bootTime > 0 {
			for _, pm := range snap.Processes {
				if pm.PID == p.PID && pm.StartTimeTicks > 0 {
					ticksPerSec := float64(100) // SC_CLK_TCK = 100 on most Linux
					procStart := bootTime + float64(pm.StartTimeTicks)/ticksPerSec
					ageSec := float64(now.Unix()) - procStart
					if ageSec >= 0 && ageSec < newnessAgeSec {
						newness = newnessBonus
					}
					break
				}
			}
		}

		composite = (composite + newness) * 100
		if composite > 100 {
			composite = 100
		}

		scores = append(scores, model.ImpactScore{
			PID:            p.PID,
			Comm:           p.Comm,
			Service:        p.ServiceName,
			Cgroup:         p.CgroupPath,
			CPUPct:         p.CPUPct,
			CPUSaturation:  cpuNorm,
			PSIContrib:     psiNorm,
			IOWait:         ioNorm,
			MemGrowth:      memNorm,
			NetRetrans:     netNorm,
			NewnessPenalty: newness,
			Composite:      composite,
			Threads:        p.NumThreads,
			RSS:            p.RSS,
			WriteMBs:       p.WriteMBs,
		})
	}

	// Sort descending by composite score
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Composite > scores[j].Composite
	})

	// Assign ranks and cap
	n := len(scores)
	if n > impactMaxProcs {
		n = impactMaxProcs
		scores = scores[:n]
	}
	for i := range scores {
		scores[i].Rank = i + 1
	}

	return scores
}

// normRatio returns v/max clamped to [0,1]. Returns 0 if max is 0.
func normRatio(v, max float64) float64 {
	if max <= 0 {
		return 0
	}
	r := v / max
	if r > 1 {
		return 1
	}
	if r < 0 {
		return 0
	}
	return r
}

// clamp01 clamps v to [0,1].
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// readBootTime returns system boot time as Unix timestamp from /proc/stat btime.
func readBootTime() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
					return v
				}
			}
		}
	}
	return 0
}
