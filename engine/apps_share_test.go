package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// Builds a minimal snapshot+rates so the enrichment can be exercised without
// touching /proc. Each app is an AppInstance keyed by PID; per-PID rates are
// fed via rates.ProcessRates with matching PIDs.
func synthScene(cpus int, memBytes uint64, apps []model.AppInstance, prs []model.ProcessRate, diskMBs float64) (*model.Snapshot, *model.RateSnapshot) {
	snap := &model.Snapshot{}
	snap.Global.CPU.NumCPUs = cpus
	snap.Global.Memory.Total = memBytes
	snap.Global.Apps.Instances = apps
	rs := &model.RateSnapshot{ProcessRates: prs}
	if diskMBs > 0 {
		rs.DiskRates = []model.DiskRate{{Name: "sda", ReadMBs: diskMBs, WriteMBs: 0}}
	}
	return snap, rs
}

func TestEnrichAppResourceShare_ComputesCapacityShare(t *testing.T) {
	snap, rates := synthScene(
		4,                      // 4 CPUs
		16*1024*1024*1024,       // 16 GiB
		[]model.AppInstance{
			{ID: "mysql", AppType: "mysql", DisplayName: "MySQL", PID: 100, Connections: 12},
			{ID: "nginx", AppType: "nginx", DisplayName: "Nginx", PID: 200, Connections: 50},
		},
		[]model.ProcessRate{
			{PID: 100, CPUPct: 180, RSS: 4 * 1024 * 1024 * 1024, ReadMBs: 12, WriteMBs: 8},
			{PID: 200, CPUPct: 40, RSS: 512 * 1024 * 1024, ReadMBs: 0, WriteMBs: 1},
		},
		50, // worst disk = 50 MB/s
	)

	EnrichAppResourceShare(snap, rates, nil, nil)

	mysql := snap.Global.Apps.Instances[0].Share
	nginx := snap.Global.Apps.Instances[1].Share

	if mysql.CPUCoresUsed < 1.7 || mysql.CPUCoresUsed > 1.9 {
		t.Errorf("mysql cores used = %.3f, want ~1.80", mysql.CPUCoresUsed)
	}
	if mysql.CPUPctOfSystem < 44 || mysql.CPUPctOfSystem > 46 {
		t.Errorf("mysql CPU%% of system = %.2f, want ~45%%", mysql.CPUPctOfSystem)
	}
	if mysql.MemPctOfSystem < 24 || mysql.MemPctOfSystem > 26 {
		t.Errorf("mysql mem%% of system = %.2f, want ~25%%", mysql.MemPctOfSystem)
	}
	// Read+Write = 20 MB/s, worst disk = 50 MB/s → 40%
	if mysql.IOPctOfBusiest < 39 || mysql.IOPctOfBusiest > 41 {
		t.Errorf("mysql IO%% of busiest = %.2f, want ~40%%", mysql.IOPctOfBusiest)
	}
	// Headroom check
	if mysql.CPUCoresHeadroom < 2.1 || mysql.CPUCoresHeadroom > 2.3 {
		t.Errorf("mysql CPU headroom = %.3f, want ~2.2 cores", mysql.CPUCoresHeadroom)
	}
	// Nginx should rank lower than mysql on CPU/mem/IO.
	if mysql.RankCPU != 1 || nginx.RankCPU != 2 {
		t.Errorf("CPU ranks = %d/%d, want 1/2", mysql.RankCPU, nginx.RankCPU)
	}
	if mysql.RankMem != 1 || nginx.RankMem != 2 {
		t.Errorf("Mem ranks = %d/%d, want 1/2", mysql.RankMem, nginx.RankMem)
	}
	// Nginx should rank first on connections (50 > 12).
	if nginx.RankNet != 1 || mysql.RankNet != 2 {
		t.Errorf("Net ranks: mysql=%d nginx=%d, want mysql=2 nginx=1",
			mysql.RankNet, nginx.RankNet)
	}
}

func TestEnrichAppResourceShare_BottleneckShareWhenIncident(t *testing.T) {
	snap, rates := synthScene(
		4, 16*1024*1024*1024,
		[]model.AppInstance{
			{ID: "mysql", AppType: "mysql", DisplayName: "MySQL", PID: 100},
			{ID: "backup", AppType: "backup", DisplayName: "Backup", PID: 200},
			{ID: "nginx", AppType: "nginx", DisplayName: "Nginx", PID: 300},
		},
		[]model.ProcessRate{
			{PID: 100, ReadMBs: 45, WriteMBs: 30}, // dominant IO user
			{PID: 200, ReadMBs: 10, WriteMBs: 5},
			{PID: 300, ReadMBs: 0, WriteMBs: 0},
		},
		100,
	)
	result := &model.AnalysisResult{
		Health:            model.HealthCritical,
		PrimaryBottleneck: "io saturation",
	}
	EnrichAppResourceShare(snap, rates, result, nil)

	mysql := snap.Global.Apps.Instances[0].Share
	backup := snap.Global.Apps.Instances[1].Share
	nginx := snap.Global.Apps.Instances[2].Share

	if mysql.BottleneckDimension != "io" {
		t.Errorf("mysql bottleneck dim = %q, want io", mysql.BottleneckDimension)
	}
	// mysql IO = 75, total = 75+15+0 = 90 → ~83%
	if mysql.BottleneckSharePct < 80 || mysql.BottleneckSharePct > 86 {
		t.Errorf("mysql bottleneck share = %.2f, want ~83%%", mysql.BottleneckSharePct)
	}
	// backup = ~17%
	if backup.BottleneckSharePct < 14 || backup.BottleneckSharePct > 20 {
		t.Errorf("backup bottleneck share = %.2f, want ~17%%", backup.BottleneckSharePct)
	}
	if nginx.BottleneckSharePct != 0 {
		t.Errorf("nginx contributes no IO, share should be 0 — got %.2f", nginx.BottleneckSharePct)
	}
}

func TestEnrichAppResourceShare_NoBottleneckNoShare(t *testing.T) {
	snap, rates := synthScene(
		2, 8*1024*1024*1024,
		[]model.AppInstance{{ID: "a", AppType: "a", PID: 1}},
		[]model.ProcessRate{{PID: 1, CPUPct: 20}},
		0,
	)
	// Healthy → no bottleneck share should be populated.
	result := &model.AnalysisResult{Health: model.HealthOK}
	EnrichAppResourceShare(snap, rates, result, nil)
	if snap.Global.Apps.Instances[0].Share.BottleneckDimension != "" {
		t.Error("healthy system should leave BottleneckDimension empty")
	}
	if snap.Global.Apps.Instances[0].Share.BottleneckSharePct != 0 {
		t.Error("healthy system should leave BottleneckSharePct zero")
	}
}

func TestNormalizedBottleneck(t *testing.T) {
	cases := map[string]string{
		"cpu saturation":   "cpu",
		"memory pressure":  "memory",
		"swap thrash":      "memory",
		"io saturation":    "io",
		"disk writeback":   "io",
		"network overload": "network",
		"unknown":          "",
	}
	for in, want := range cases {
		if got := normalizedBottleneck(in); got != want {
			t.Errorf("normalizedBottleneck(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRankApps_TieBehavior(t *testing.T) {
	apps := []model.AppInstance{
		{ID: "a", PID: 1},
		{ID: "b", PID: 2},
		{ID: "c", PID: 3},
	}
	// Two equal values at 5, one at 2: standard competition ranking gives 1,1,3.
	apps[0].Share.CPUCoresUsed = 5
	apps[1].Share.CPUCoresUsed = 5
	apps[2].Share.CPUCoresUsed = 2
	rankApps(apps,
		func(a *model.AppInstance) float64 { return a.Share.CPUCoresUsed },
		func(a *model.AppInstance, r int) { a.Share.RankCPU = r })
	if apps[0].Share.RankCPU != 1 || apps[1].Share.RankCPU != 1 {
		t.Errorf("tied values should share rank 1: got %d and %d",
			apps[0].Share.RankCPU, apps[1].Share.RankCPU)
	}
	if apps[2].Share.RankCPU != 3 {
		t.Errorf("third rank after two-way tie = %d, want 3", apps[2].Share.RankCPU)
	}
}

func TestRankApps_ZeroValuesUnranked(t *testing.T) {
	apps := []model.AppInstance{
		{ID: "busy", PID: 1},
		{ID: "idle", PID: 2},
	}
	apps[0].Share.CPUCoresUsed = 1.5
	apps[1].Share.CPUCoresUsed = 0
	rankApps(apps,
		func(a *model.AppInstance) float64 { return a.Share.CPUCoresUsed },
		func(a *model.AppInstance, r int) { a.Share.RankCPU = r })
	if apps[0].Share.RankCPU != 1 {
		t.Errorf("busy app rank = %d, want 1", apps[0].Share.RankCPU)
	}
	if apps[1].Share.RankCPU != 0 {
		t.Errorf("idle app rank = %d, want 0 (unranked)", apps[1].Share.RankCPU)
	}
}
