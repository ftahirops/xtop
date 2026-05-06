package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

func snapWithApp(pid int, appName, cgroup string) *model.Snapshot {
	return &model.Snapshot{
		Global: model.GlobalMetrics{
			AppIdentities: map[int]model.AppIdentity{
				pid: {
					PID:        pid,
					AppName:    appName,
					CgroupPath: cgroup,
					Comm:       appName,
				},
			},
		},
	}
}

func ratesWithProcess(pid int, cpuPct float64, rssBytes uint64) *model.RateSnapshot {
	return &model.RateSnapshot{
		ProcessRates: []model.ProcessRate{
			{PID: pid, Comm: "x", CPUPct: cpuPct, RSS: rssBytes},
		},
	}
}

// TestAppBaseline_NormalLoad does NOT emit anomaly: current value is close to
// the learned baseline for this hour-of-week.
func TestAppBaseline_NormalLoad(t *testing.T) {
	hist := NewHistory(10, 3)
	snap := snapWithApp(1234, "postgres", "/system.slice/postgres.service")

	// Warm up with realistic noise — std ~1.6 so a small variation around
	// the mean stays inside the 3σ band.
	cpu := []float64{28, 30, 32}
	for i := 0; i < 200; i++ {
		UpdateAppBaselines(snap, ratesWithProcess(1234, cpu[i%3], 200<<20), hist, false)
	}

	// 30.5 is well within band (~0.3σ).
	got := UpdateAppBaselines(snap, ratesWithProcess(1234, 30.5, 200<<20), hist, false)
	for _, a := range got {
		if a.AppName == "postgres" && a.Sigma >= appBaselineSigma {
			t.Errorf("expected no anomaly for normal load, got sigma=%v", a.Sigma)
		}
	}
}

// TestAppBaseline_AbnormalLoad: after warm-up, a value far from the band
// must produce an anomaly with the right sign.
func TestAppBaseline_AbnormalLoad(t *testing.T) {
	hist := NewHistory(10, 3)
	snap := snapWithApp(1234, "postgres", "/system.slice/postgres.service")

	// Warm up baseline at moderate CPU. Need values above ~25 to avoid
	// EWMA's count<warmup outlier-rejection blocking convergence.
	for i := 0; i < 200; i++ {
		UpdateAppBaselines(snap, ratesWithProcess(1234, 30.0+float64(i%3), 200<<20), hist, false)
	}

	// Spike CPU well outside the band.
	got := UpdateAppBaselines(snap, ratesWithProcess(1234, 250.0, 200<<20), hist, false)

	found := false
	for _, a := range got {
		if a.AppName == "postgres" && a.Metric == "cpu_pct" && a.Sigma >= appBaselineSigma {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cpu_pct anomaly for postgres, got %+v", got)
	}
}

// TestAppBaseline_FrozenDuringIncident: frozen=true must not update the
// baseline, even though it still scores anomalies. Verified by checking that
// after a frozen sequence, the baseline is unchanged from a control hist.
func TestAppBaseline_FrozenDuringIncident(t *testing.T) {
	histFrozen := NewHistory(10, 3)
	histLive := NewHistory(10, 3)
	snap := snapWithApp(1234, "redis", "/system.slice/redis.service")

	// Warm up both with normal load (values >= 25 so EWMA outlier-guard doesn't block).
	for i := 0; i < 200; i++ {
		UpdateAppBaselines(snap, ratesWithProcess(1234, 30.0+float64(i%3), 100<<20), histFrozen, false)
		UpdateAppBaselines(snap, ratesWithProcess(1234, 30.0+float64(i%3), 100<<20), histLive, false)
	}

	// Now feed a sustained spike. Frozen does NOT update; live DOES.
	for i := 0; i < 50; i++ {
		UpdateAppBaselines(snap, ratesWithProcess(1234, 95.0, 100<<20), histFrozen, true)
		UpdateAppBaselines(snap, ratesWithProcess(1234, 95.0, 100<<20), histLive, false)
	}

	// After incident, frozen tracker's baseline is still around the warm-up
	// values, but live tracker has absorbed the spike.
	how := hourOfWeek(time.Now())
	key := appKey("redis", "cpu_pct", how)
	mFrozen, _, _, _ := getAppBaselineStore(histFrozen).updateAndScore(key, 30.0, true) // freeze=true so just read
	mLive, _, _, _ := getAppBaselineStore(histLive).updateAndScore(key, 30.0, true)

	if mLive <= mFrozen+10 {
		t.Errorf("live mean (%.2f) should have drifted up significantly; frozen mean (%.2f) should not", mLive, mFrozen)
	}
}

// TestHourOfWeek_Monday: Monday 00:00 UTC = 0.
func TestHourOfWeek_Monday(t *testing.T) {
	mon := time.Date(2025, 1, 6, 0, 0, 0, 0, time.UTC) // 2025-01-06 was a Monday
	if got := hourOfWeek(mon); got != 0 {
		t.Errorf("hourOfWeek(Mon 00:00) = %d, want 0", got)
	}
	sunNoon := time.Date(2025, 1, 12, 12, 0, 0, 0, time.UTC) // following Sunday noon
	if got := hourOfWeek(sunNoon); got != 6*24+12 {
		t.Errorf("hourOfWeek(Sun 12:00) = %d, want %d", got, 6*24+12)
	}
}
