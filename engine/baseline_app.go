package engine

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// appBaselineBucket is a Welford-style running mean/variance, with a hard
// minimum sample count for "warmed up" — much simpler and more predictable
// than the EWMA outlier-guard machinery used by SeasonalTracker. We use one
// bucket per (app, metric, hour-of-week).
//
// Welford gives exact mean+variance over the full sample window with no
// warmup quirks, and the implementation fits in ~10 lines.
type appBaselineBucket struct {
	count int64
	mean  float64
	m2    float64 // sum of squared deltas
}

func (b *appBaselineBucket) push(v float64) {
	b.count++
	delta := v - b.mean
	b.mean += delta / float64(b.count)
	delta2 := v - b.mean
	b.m2 += delta * delta2
}

func (b *appBaselineBucket) stats() (mean, std float64, ready bool) {
	if b.count < int64(appBaselineMinSamples) {
		return b.mean, 0, false
	}
	if b.count < 2 {
		return b.mean, 0, false
	}
	variance := b.m2 / float64(b.count-1)
	return b.mean, math.Sqrt(variance), true
}

// appBaselineStore is a thread-safe map of per-(app, metric, hour-of-week)
// Welford trackers. Lifetime: process. TODO: persist to ~/.xtop/store.db.
type appBaselineStore struct {
	mu      sync.Mutex
	buckets map[string]*appBaselineBucket
}

func newAppBaselineStore() *appBaselineStore {
	return &appBaselineStore{buckets: make(map[string]*appBaselineBucket)}
}

func (s *appBaselineStore) updateAndScore(key string, v float64, freeze bool) (mean, std float64, sigma float64, ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		b = &appBaselineBucket{}
		s.buckets[key] = b
	}
	if !freeze {
		b.push(v)
	}
	mean, std, ready = b.stats()
	if !ready || std < 1e-9 {
		return mean, std, 0, ready
	}
	sigma = (v - mean) / std
	return mean, std, sigma, true
}

// appBaselines is a process-lifetime store. Keyed by hist pointer so multiple
// engines (tests, parallel hosts via fleet hub) don't share state.
//
// Cleanup: Engine.Close calls forgetAppBaselines(history) so test runs and
// short-lived engines (xtop why / loadshare) don't accumulate entries here.
// Without this, every `go test -count=N` would leak N entries.
var (
	appBaselinesMu sync.Mutex
	appBaselines   = make(map[*History]*appBaselineStore)
)

func getAppBaselineStore(h *History) *appBaselineStore {
	appBaselinesMu.Lock()
	defer appBaselinesMu.Unlock()
	if s, ok := appBaselines[h]; ok {
		return s
	}
	s := newAppBaselineStore()
	appBaselines[h] = s
	return s
}

// forgetAppBaselines drops the per-history Welford state from the global
// store. Called by Engine.Close. Safe to call with an unknown history.
func forgetAppBaselines(h *History) {
	if h == nil {
		return
	}
	appBaselinesMu.Lock()
	delete(appBaselines, h)
	appBaselinesMu.Unlock()
}

// Phase 4: per-app behavioral baselines.
//
// Anchored on cgroup-derived app role (e.g. "postgres", "nginx"), per-hour-of-
// week. The baseline learns "what's normal for this app at this time" so that
// a workload-typical CPU spike doesn't trip an alert, but the same spike at
// 03:00 Sunday does.
//
// Storage: piggybacks on the existing SeasonalTracker (per-hour-of-day EWMA).
// We extend the key to encode hour-of-week (mon 00:00 = 0, sun 23:00 = 167)
// so weekday/weekend distributions stay separate. SeasonalTracker is a
// 24-bucket array internally — we store 168 keys instead of one. Memory cost:
// ~168 × ~40B per app metric = ~7KB per app per metric. Negligible.
//
// Frozen-during-incident: when a Confirmed incident is active, we DO NOT
// update baselines. This prevents the incident's bad data from being absorbed
// into "normal." This is the single biggest learning-time correctness rule
// per Google SRE practice.
//
// Cold-start: when the per-(app, hour-of-week) bucket has fewer samples than
// appBaselineMinSamples, no anomaly is emitted. The Note field on the result
// indicates "cold-start".
//
// TODO future: persist these baselines to SQLite (store/) so they survive
// restarts; share across the fleet hub for cross-host priors.

const (
	// appBaselineSigma is the z-score threshold for emitting an anomaly.
	// 3.0 ≈ 0.27% expected false-positive rate on a normal distribution.
	appBaselineSigma = 3.0

	// appBaselineMinSamples is the warm-up gate; below this, no anomaly fires.
	appBaselineMinSamples = 20

	// appCPUMinPct is the minimum CPU% to bother tracking (filters out idle apps).
	appCPUMinPct = 0.5

	// appRSSMinMB is the minimum RSS to bother tracking.
	appRSSMinMB = 50.0
)

// hourOfWeek maps a time to 0..167 with Monday 00:00 = 0.
func hourOfWeek(t time.Time) int {
	w := int(t.Weekday())
	// time.Weekday: Sunday=0..Saturday=6. Convert to Mon=0..Sun=6.
	w = (w + 6) % 7
	return w*24 + t.Hour()
}

// appKey builds the seasonal-tracker key for a given app+metric+how.
func appKey(app, metric string, how int) string {
	return fmt.Sprintf("app:%s:%s:%03d", app, metric, how)
}

// appRolesFromIdentities groups PIDs by resolved app name (or comm fallback)
// and returns a map of app-role → list of PIDs. Cgroup-anchored apps win;
// PIDs without a recognized app are grouped by comm. PIDs with neither
// CgroupPath nor a clear identity are skipped.
func appRolesFromIdentities(snap *model.Snapshot) map[string][]int {
	roles := make(map[string][]int)
	if snap == nil || snap.Global.AppIdentities == nil {
		return roles
	}
	for pid, id := range snap.Global.AppIdentities {
		if id.CgroupPath == "" && id.AppName == "" {
			continue
		}
		role := id.AppName
		if role == "" {
			role = id.Comm
		}
		if role == "" {
			continue
		}
		roles[role] = append(roles[role], pid)
	}
	return roles
}

// processSummaryForApp aggregates CPU% and RSS MB across PIDs of an app.
// We sum CPU (instances of the same app cumulatively load the host) and
// take max RSS (best proxy for working-set size when there are workers).
func processSummaryForApp(pids []int, rates *model.RateSnapshot, snap *model.Snapshot) (cpuPct, rssMB float64, sampled bool) {
	if rates == nil {
		return 0, 0, false
	}
	pidSet := make(map[int]struct{}, len(pids))
	for _, p := range pids {
		pidSet[p] = struct{}{}
	}
	for _, pr := range rates.ProcessRates {
		if _, ok := pidSet[pr.PID]; !ok {
			continue
		}
		cpuPct += pr.CPUPct
		mb := float64(pr.RSS) / (1024 * 1024)
		if mb > rssMB {
			rssMB = mb
		}
		sampled = true
	}
	return cpuPct, rssMB, sampled
}

// UpdateAppBaselines feeds the per-app baseline trackers and emits anomalies.
// Returns the anomaly list to be attached to the analysis result.
//
// frozen=true means "do not update the baseline, just check for anomalies"
// — used while an incident is Confirmed/Active so bad data isn't absorbed.
func UpdateAppBaselines(snap *model.Snapshot, rates *model.RateSnapshot, hist *History, frozen bool) []model.AppBehaviorAnomaly {
	if snap == nil || rates == nil || hist == nil {
		return nil
	}

	how := hourOfWeek(time.Now())
	roles := appRolesFromIdentities(snap)
	if len(roles) == 0 {
		return nil
	}

	var anomalies []model.AppBehaviorAnomaly

	for role, pids := range roles {
		cpu, rss, sampled := processSummaryForApp(pids, rates, snap)
		if !sampled {
			continue
		}

		anomalies = append(anomalies, scoreAppMetric(role, "cpu_pct", cpu, how, hist, frozen, appCPUMinPct, snap.Global.AppIdentities, pids)...)
		anomalies = append(anomalies, scoreAppMetric(role, "rss_mb", rss, how, hist, frozen, appRSSMinMB, snap.Global.AppIdentities, pids)...)
	}

	// Stable order for reproducible traces / tests.
	sort.Slice(anomalies, func(i, j int) bool {
		if anomalies[i].AppName != anomalies[j].AppName {
			return anomalies[i].AppName < anomalies[j].AppName
		}
		return anomalies[i].Metric < anomalies[j].Metric
	})
	return anomalies
}

// scoreAppMetric updates the per-app baseline for one (app, metric, how) and
// emits an anomaly if outside the band. Returns 0 or 1 anomalies.
func scoreAppMetric(
	role, metric string, value float64, how int,
	hist *History, frozen bool, minValue float64,
	identities map[int]model.AppIdentity, pids []int,
) []model.AppBehaviorAnomaly {
	if value < minValue {
		return nil
	}
	key := appKey(role, metric, how)
	store := getAppBaselineStore(hist)
	mean, std, sigma, ready := store.updateAndScore(key, value, frozen)
	if !ready || sigma < appBaselineSigma {
		return nil
	}
	note := ""
	if frozen {
		note = "frozen-during-incident"
	}
	return []model.AppBehaviorAnomaly{{
		AppName:      role,
		CgroupPath:   cgroupForFirstPID(pids, identities),
		Metric:       metric,
		Current:      value,
		HourBaseline: mean,
		HourStdDev:   std,
		Sigma:        sigma,
		HourOfWeek:   how,
		Note:         note,
	}}
}

func cgroupForFirstPID(pids []int, identities map[int]model.AppIdentity) string {
	for _, p := range pids {
		if id, ok := identities[p]; ok && id.CgroupPath != "" {
			return id.CgroupPath
		}
	}
	return ""
}
