package engine

import (
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// EnrichAppResourceShare fills in the SRE "resource share" view for every
// detected app in snap.Global.Apps.Instances. Keeps each dimension separate
// (we never aggregate CPU+mem+IO into a composite percentage — that's an
// anti-pattern) and adds per-dimension ranks plus a bottleneck-share column
// when an incident is active.
//
// Inputs:
//
//   - snap: the live snapshot — for app list, NumCPUs, MemTotal.
//   - rates: per-process + per-disk rates (gives us IO MB/s per PID and the
//     worst disk's utilization baseline for IOPctOfBusiest).
//   - result: the current AnalysisResult — if an incident is firing, its
//     PrimaryBottleneck drives the BottleneckShare computation.
//   - scores: ImpactScores the caller has already computed. Passing nil is
//     fine; apps just won't show an impact number.
//
// The function is a pure enrichment pass: it mutates the Share field on
// existing AppInstance entries and never adds/removes apps.
func EnrichAppResourceShare(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, scores []model.ImpactScore) {
	if snap == nil || len(snap.Global.Apps.Instances) == 0 {
		return
	}

	// Build a fast PID → process-rate lookup. A single app may own many PIDs
	// (think php-fpm, nginx worker pool), so we later aggregate per app.
	var byPID map[int]*model.ProcessRate
	if rates != nil {
		byPID = make(map[int]*model.ProcessRate, len(rates.ProcessRates))
		for i := range rates.ProcessRates {
			byPID[rates.ProcessRates[i].PID] = &rates.ProcessRates[i]
		}
	}

	numCPUs := snap.Global.CPU.NumCPUs
	if numCPUs <= 0 {
		numCPUs = 1
	}
	memTotal := snap.Global.Memory.Total

	// Worst-disk MB/s gives us a denominator for IOPctOfBusiest so the rank
	// is expressed as "% of the noisiest disk," which is what SREs actually
	// compare against.
	worstDiskMBs := worstDiskThroughput(rates)

	// First pass: compute per-dimension absolute values for each app.
	apps := snap.Global.Apps.Instances
	for i := range apps {
		a := &apps[i]
		s := &a.Share

		// Start fresh each tick.
		*s = model.AppResourceShare{}

		// Aggregate across every PID in the app's process group / cgroup.
		// We rely on app.PID as the primary; for multi-PID apps (php-fpm,
		// nginx) we include children whose comm or cgroup matches the app.
		pids := processesForApp(a, rates)
		for _, pid := range pids {
			pr := byPID[pid]
			if pr == nil {
				continue
			}
			// CPUPct on ProcessRate is already system-relative (0..100*N)
			// — convert back to cores for headroom math.
			s.CPUCoresUsed += pr.CPUPct / 100.0
			s.MemRSSBytes += pr.RSS
			s.ReadMBs += pr.ReadMBs
			s.WriteMBs += pr.WriteMBs
		}
		// For single-PID apps we may miss children; fall back to the
		// advertised app-level CPU if aggregation came up empty.
		if s.CPUCoresUsed == 0 && a.CPUPct > 0 {
			s.CPUCoresUsed = a.CPUPct / 100.0
		}
		if s.MemRSSBytes == 0 && a.RSSMB > 0 {
			s.MemRSSBytes = uint64(a.RSSMB * 1024 * 1024)
		}
		s.NetConns = a.Connections

		// Share-of-capacity — independent per dimension. Cap at 100 so a
		// small measurement jitter doesn't produce "102%."
		s.CPUPctOfSystem = clampPct(s.CPUCoresUsed / float64(numCPUs) * 100)
		if memTotal > 0 {
			s.MemPctOfSystem = clampPct(float64(s.MemRSSBytes) / float64(memTotal) * 100)
		}
		if worstDiskMBs > 0 {
			s.IOPctOfBusiest = clampPct((s.ReadMBs + s.WriteMBs) / worstDiskMBs * 100)
		}

		// Headroom — the most useful framing: "how much room is left."
		s.CPUCoresHeadroom = float64(numCPUs) - s.CPUCoresUsed
		if s.CPUCoresHeadroom < 0 {
			s.CPUCoresHeadroom = 0
		}
		if memTotal > s.MemRSSBytes {
			s.MemBytesHeadroom = memTotal - s.MemRSSBytes
		}

		// Impact: reuse the engine's ImpactScore for the app's primary PID.
		// Using the top PID's score is a deliberate choice — a noisy worker
		// in a pool already flags the whole app, and ImpactScore is
		// calibrated on the single-process scale.
		s.Impact = impactScoreFor(scores, a.PID)
	}

	// Second pass: rank each dimension across apps.
	rankApps(apps, func(a *model.AppInstance) float64 { return a.Share.CPUCoresUsed }, func(a *model.AppInstance, r int) { a.Share.RankCPU = r })
	rankApps(apps, func(a *model.AppInstance) float64 { return float64(a.Share.MemRSSBytes) }, func(a *model.AppInstance, r int) { a.Share.RankMem = r })
	rankApps(apps, func(a *model.AppInstance) float64 { return a.Share.ReadMBs + a.Share.WriteMBs }, func(a *model.AppInstance, r int) { a.Share.RankIO = r })
	rankApps(apps, func(a *model.AppInstance) float64 { return float64(a.Share.NetConns) }, func(a *model.AppInstance, r int) { a.Share.RankNet = r })

	// Third pass: when an incident is active, compute each app's
	// contribution to the firing bottleneck. This is the single most
	// actionable column — it directly answers "who is causing this?"
	if result != nil && result.Health > model.HealthOK && result.PrimaryBottleneck != "" {
		dim := normalizedBottleneck(result.PrimaryBottleneck)
		totals := dimensionTotals(apps)
		for i := range apps {
			a := &apps[i]
			a.Share.BottleneckDimension = dim
			switch dim {
			case "cpu":
				if totals.cpu > 0 {
					a.Share.BottleneckSharePct = clampPct(a.Share.CPUCoresUsed / totals.cpu * 100)
				}
			case "memory":
				if totals.mem > 0 {
					a.Share.BottleneckSharePct = clampPct(float64(a.Share.MemRSSBytes) / totals.mem * 100)
				}
			case "io":
				if totals.io > 0 {
					a.Share.BottleneckSharePct = clampPct((a.Share.ReadMBs + a.Share.WriteMBs) / totals.io * 100)
				}
			case "network":
				if totals.net > 0 {
					a.Share.BottleneckSharePct = clampPct(float64(a.Share.NetConns) / totals.net * 100)
				}
			}
		}
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

type dimTotals struct {
	cpu float64 // cores used across apps
	mem float64 // bytes used
	io  float64 // MB/s (read+write)
	net float64 // connection count
}

func dimensionTotals(apps []model.AppInstance) dimTotals {
	var t dimTotals
	for _, a := range apps {
		t.cpu += a.Share.CPUCoresUsed
		t.mem += float64(a.Share.MemRSSBytes)
		t.io += a.Share.ReadMBs + a.Share.WriteMBs
		t.net += float64(a.Share.NetConns)
	}
	return t
}

// processesForApp returns the PIDs we should aggregate for this app. The
// app's own PID is always included. For apps with a recognizable cgroup
// (php-fpm, nginx worker pool, docker-managed services), we also pick up
// sibling processes whose ProcessRate.ServiceName matches the app name.
func processesForApp(a *model.AppInstance, rates *model.RateSnapshot) []int {
	pids := []int{a.PID}
	if rates == nil {
		return pids
	}
	lowerApp := strings.ToLower(a.AppType)
	for i := range rates.ProcessRates {
		p := &rates.ProcessRates[i]
		if p.PID == a.PID {
			continue
		}
		svc := strings.ToLower(p.ServiceName)
		comm := strings.ToLower(p.Comm)
		if lowerApp == "" {
			continue
		}
		if strings.Contains(svc, lowerApp) || strings.Contains(comm, lowerApp) {
			pids = append(pids, p.PID)
		}
	}
	return pids
}

// worstDiskThroughput returns the sum-busiest disk's read+write MB/s. Used
// as the denominator for IOPctOfBusiest. Returns 0 when we have no disk
// data (rates absent, or no non-zero disk).
func worstDiskThroughput(rates *model.RateSnapshot) float64 {
	if rates == nil {
		return 0
	}
	var worst float64
	for _, d := range rates.DiskRates {
		total := d.ReadMBs + d.WriteMBs
		if total > worst {
			worst = total
		}
	}
	return worst
}

// impactScoreFor looks up the ImpactScore for a PID in the supplied slice.
// Returns 0 when no score exists (no process data / low-activity PID /
// scores not computed by the caller).
func impactScoreFor(scores []model.ImpactScore, pid int) float64 {
	if pid <= 0 {
		return 0
	}
	for _, s := range scores {
		if s.PID == pid {
			return s.Composite
		}
	}
	return 0
}

// normalizedBottleneck maps the many bottleneck labels the engine may emit
// into the four canonical dimensions we rank apps on.
func normalizedBottleneck(b string) string {
	b = strings.ToLower(b)
	switch {
	case strings.Contains(b, "cpu"):
		return "cpu"
	case strings.Contains(b, "mem"), strings.Contains(b, "swap"), strings.Contains(b, "reclaim"):
		return "memory"
	case strings.Contains(b, "io"), strings.Contains(b, "disk"), strings.Contains(b, "fs"):
		return "io"
	case strings.Contains(b, "net"):
		return "network"
	}
	return ""
}

// rankApps assigns a 1-based rank to each app based on a descending sort of
// the value extracted by pick(). Apps that tie on value share the lower rank
// (standard competition ranking). Apps with value <= 0 get rank 0 (unranked)
// so the UI can render "—" instead of confusing them with near-zero users.
func rankApps(apps []model.AppInstance, pick func(*model.AppInstance) float64, set func(*model.AppInstance, int)) {
	type idxVal struct {
		i int
		v float64
	}
	pairs := make([]idxVal, 0, len(apps))
	for i := range apps {
		v := pick(&apps[i])
		pairs = append(pairs, idxVal{i: i, v: v})
	}
	sort.Slice(pairs, func(a, b int) bool { return pairs[a].v > pairs[b].v })
	rank := 0
	lastVal := -1.0
	for pos, p := range pairs {
		if p.v <= 0 {
			set(&apps[p.i], 0)
			continue
		}
		if p.v != lastVal {
			rank = pos + 1
			lastVal = p.v
		}
		set(&apps[p.i], rank)
	}
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
