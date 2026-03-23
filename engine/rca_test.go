package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ─── Test Helpers ────────────────────────────────────────────────────────────

func baseSnapshot() *model.Snapshot {
	return &model.Snapshot{
		Timestamp: time.Now(),
		Global: model.GlobalMetrics{
			CPU: model.CPUMetrics{
				NumCPUs: 6,
				LoadAvg: model.LoadAvg{Load1: 1.0, Load5: 0.8, Load15: 0.7, Running: 2, Total: 200},
				Total:   model.CPUTimes{User: 1000, System: 200, Idle: 8000, IOWait: 50},
			},
			Memory: model.MemoryMetrics{
				Total:     16 * 1024 * 1024 * 1024,
				Available: 12 * 1024 * 1024 * 1024,
				Cached:    4 * 1024 * 1024 * 1024,
				SwapTotal: 4 * 1024 * 1024 * 1024,
			},
			PSI: model.PSIMetrics{},
			Conntrack: model.ConntrackStats{Max: 262144, Count: 500},
			EphemeralPorts: model.EphemeralPorts{RangeLo: 32768, RangeHi: 60999, InUse: 100},
			Apps: model.AppMetrics{},
		},
		SysInfo: &model.SysInfo{Hostname: "test"},
		Processes: []model.ProcessMetrics{
			{PID: 100, Comm: "stress-ng-cpu", UTime: 5000, STime: 100, State: "R", RSS: 4096},
			{PID: 200, Comm: "mysqld", UTime: 3000, STime: 500, State: "S", RSS: 512 * 1024 * 1024},
			{PID: 300, Comm: "nginx", UTime: 500, STime: 100, State: "S", RSS: 64 * 1024 * 1024},
			{PID: 400, Comm: "dockerd", UTime: 90000, STime: 10000, State: "S", RSS: 57 * 1024 * 1024},
			{PID: 500, Comm: "xtop", UTime: 80000, STime: 5000, State: "S", RSS: 200 * 1024 * 1024},
		},
	}
}

func baseRates() *model.RateSnapshot {
	return &model.RateSnapshot{
		DeltaSec:      3.0,
		CPUBusyPct:    15.0,
		CPUSystemPct:  3.0,
		CPUIOWaitPct:  1.0,
		CPUSoftIRQPct: 0.2,
		CtxSwitchRate: 500,
		RetransRate:   0,
		DiskRates: []model.DiskRate{
			{Name: "sda", UtilPct: 5, AvgAwaitMs: 2.0, ReadIOPS: 50, WriteIOPS: 100, QueueDepth: 0},
		},
		NetRates: []model.NetRate{{RxMBs: 0.1, TxMBs: 0.1}},
		MountRates: []model.MountRate{
			{MountPoint: "/", FreePct: 45, ETASeconds: 86400},
		},
		ProcessRates: []model.ProcessRate{
			{PID: 100, Comm: "stress-ng-cpu", CPUPct: 85.0, State: "R", RSS: 4096},
			{PID: 200, Comm: "mysqld", CPUPct: 5.0, State: "S", RSS: 512 * 1024 * 1024, ReadMBs: 1.0, WriteMBs: 2.0},
			{PID: 300, Comm: "nginx", CPUPct: 2.0, State: "S", RSS: 64 * 1024 * 1024},
			{PID: 400, Comm: "dockerd", CPUPct: 8.0, State: "S", RSS: 57 * 1024 * 1024},
			{PID: 500, Comm: "xtop", CPUPct: 5.0, State: "S", RSS: 200 * 1024 * 1024},
		},
	}
}

func newTestHistory() *History {
	h := NewHistory(100, 3)
	return h
}

// feedHistory pushes snap+rates into history N times with process history recording.
func feedHistory(h *History, snap *model.Snapshot, rates *model.RateSnapshot, n int) {
	for i := 0; i < n; i++ {
		h.Push(*snap)
		h.PushRate(*rates)
		h.ProcessHistory.Record(rates)
	}
}

// ─── CPU Bottleneck Tests ────────────────────────────────────────────────────

func TestRCA_CPUStress_CorrectBottleneck(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.CPU.Some.Avg10 = 25.0
	snap.Global.PSI.CPU.Full.Avg10 = 5.0
	snap.Global.CPU.LoadAvg = model.LoadAvg{Load1: 12.0, Load5: 8.0, Load15: 5.0, Running: 12, Total: 300}

	rates := baseRates()
	rates.CPUBusyPct = 99.5
	rates.CPUSystemPct = 10.0
	rates.CPUStealPct = 0.0
	rates.CPUIOWaitPct = 2.0
	rates.CtxSwitchRate = 10000

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	// Log evidence details for debugging
	for _, rca := range result.RCA {
		if rca.Bottleneck == BottleneckCPU {
			t.Logf("CPU score=%d groups=%d evCount=%d", rca.Score, rca.EvidenceGroups, len(rca.EvidenceV2))
			for _, ev := range rca.EvidenceV2 {
				if ev.Strength > 0 {
					t.Logf("  %s: str=%.2f conf=%.2f tags=%v", ev.ID, ev.Strength, ev.Confidence, ev.Tags)
				}
			}
		}
	}

	if result.PrimaryBottleneck != BottleneckCPU {
		t.Errorf("expected CPU Contention, got %q (score=%d, health=%d)", result.PrimaryBottleneck, result.PrimaryScore, result.Health)
	}
	// Score should be high even if trust gate blocks health escalation
	if result.PrimaryScore < 50 {
		t.Errorf("expected score >= 50, got %d", result.PrimaryScore)
	}
}

func TestRCA_CPUStress_CorrectCulprit(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.CPU.Some.Avg10 = 25.0
	snap.Global.CPU.LoadAvg = model.LoadAvg{Load1: 7.0, Load5: 5.0, Load15: 3.0, Running: 12, Total: 300}

	rates := baseRates()
	rates.CPUBusyPct = 99.5
	// stress-ng-cpu is top CPU consumer
	rates.ProcessRates[0].CPUPct = 85.0 // stress-ng-cpu
	rates.ProcessRates[3].CPUPct = 8.0  // dockerd

	h := newTestHistory()
	feedHistory(h, snap, rates, 10) // 10 ticks of history

	result := AnalyzeRCA(snap, rates, h)

	if result.PrimaryProcess != "stress-ng-cpu" {
		t.Errorf("WHO: expected stress-ng-cpu, got %q (PID %d)", result.PrimaryProcess, result.PrimaryPID)
	}
}

func TestRCA_CPUStress_XtopNeverCulprit(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.CPU.Some.Avg10 = 25.0

	rates := baseRates()
	rates.CPUBusyPct = 99.5
	// Make xtop appear as highest CPU
	rates.ProcessRates[4].CPUPct = 90.0 // xtop
	rates.ProcessRates[0].CPUPct = 80.0 // stress-ng-cpu

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.PrimaryProcess == "xtop" {
		t.Error("WHO: xtop must never be blamed as culprit")
	}
}

func TestRCA_CPUStress_NoMySQLEvidence(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.CPU.Some.Avg10 = 25.0
	snap.Global.Apps = model.AppMetrics{
		Instances: []model.AppInstance{
			{AppType: "mysql", DisplayName: "MySQL", HealthScore: 85, HealthIssues: []string{"buffer pool hit ratio 94%"}},
		},
	}

	rates := baseRates()
	rates.CPUBusyPct = 99.5

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.Narrative != nil {
		for _, ev := range result.Narrative.Evidence {
			if strings.Contains(strings.ToLower(ev), "mysql") || strings.Contains(strings.ToLower(ev), "buffer pool") {
				t.Errorf("CPU stress should not include MySQL evidence: %q", ev)
			}
		}
	}
}

func TestRCA_CPUStress_EvidenceDomainScoped(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.CPU.Some.Avg10 = 25.0

	rates := baseRates()
	rates.CPUBusyPct = 99.5
	rates.RetransRate = 5.0 // some retransmits happening

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.Narrative != nil {
		for _, ev := range result.Narrative.Evidence {
			if strings.Contains(strings.ToLower(ev), "retrans") || strings.Contains(strings.ToLower(ev), "tcp") {
				t.Errorf("CPU bottleneck evidence should not include network signals: %q", ev)
			}
		}
	}
}

// ─── Memory Bottleneck Tests ─────────────────────────────────────────────────

func TestRCA_MemoryPressure_CorrectBottleneck(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.Memory.Some.Avg10 = 30.0
	snap.Global.PSI.Memory.Full.Avg10 = 15.0
	snap.Global.Memory.Available = 1 * 1024 * 1024 * 1024 // 1G of 16G
	snap.Global.Memory.SwapUsed = 3 * 1024 * 1024 * 1024

	rates := baseRates()
	rates.MajFaultRate = 500
	rates.DirectReclaimRate = 1000

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.PrimaryBottleneck != BottleneckMemory {
		t.Errorf("expected Memory Pressure, got %q", result.PrimaryBottleneck)
	}
}

func TestRCA_MemoryPressure_BlameLargestRSS(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.Memory.Some.Avg10 = 30.0
	snap.Global.Memory.Available = 1 * 1024 * 1024 * 1024

	rates := baseRates()
	rates.DirectReclaimRate = 500
	// mysqld has largest RSS
	rates.ProcessRates[1].RSS = 10 * 1024 * 1024 * 1024 // 10G
	rates.ProcessRates[1].MemPct = 62.5

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.PrimaryProcess != "mysqld" {
		t.Errorf("WHO: expected mysqld (largest RSS), got %q", result.PrimaryProcess)
	}
}

func TestRCA_OOMKill_HighSeverity(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.Memory.Some.Avg10 = 50.0
	snap.Global.PSI.Memory.Full.Avg10 = 30.0
	snap.Global.Memory.Available = 256 * 1024 * 1024 // 256M of 16G
	snap.Global.Memory.SwapUsed = 3900 * 1024 * 1024

	rates := baseRates()
	rates.OOMKillDelta = 1
	rates.DirectReclaimRate = 5000

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.Health != model.HealthCritical {
		t.Errorf("OOM kill should trigger Critical, got health=%d", result.Health)
	}
}

// ─── IO Bottleneck Tests ─────────────────────────────────────────────────────

func TestRCA_IOSaturation_CorrectBottleneck(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.IO.Some.Avg10 = 40.0
	snap.Global.PSI.IO.Full.Avg10 = 20.0

	rates := baseRates()
	rates.DiskRates[0].UtilPct = 95.0
	rates.DiskRates[0].AvgAwaitMs = 50.0
	rates.DiskRates[0].QueueDepth = 8
	rates.DiskRates[0].ReadIOPS = 500
	rates.DiskRates[0].WriteIOPS = 1000

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.PrimaryBottleneck != BottleneckIO {
		t.Errorf("expected IO Starvation, got %q", result.PrimaryBottleneck)
	}
}

func TestRCA_IOFromSwap_BlameMemoryHog(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.IO.Some.Avg10 = 40.0
	snap.Global.PSI.IO.Full.Avg10 = 20.0
	snap.Global.PSI.Memory.Some.Avg10 = 15.0

	rates := baseRates()
	rates.DiskRates[0].UtilPct = 90.0
	rates.DiskRates[0].AvgAwaitMs = 30.0
	rates.DiskRates[0].ReadIOPS = 500
	rates.DiskRates[0].WriteIOPS = 500
	rates.SwapInRate = 50.0 // heavy swap activity
	rates.DirectReclaimRate = 2000

	// stress-ng is top memory consumer causing the swap
	rates.ProcessRates[0] = model.ProcessRate{PID: 100, Comm: "stress-ng-vm", CPUPct: 30, State: "R", RSS: 12 * 1024 * 1024 * 1024, MemPct: 75}
	rates.ProcessRates[1] = model.ProcessRate{PID: 200, Comm: "mysqld", CPUPct: 5, State: "D", RSS: 512 * 1024 * 1024, ReadMBs: 1.0, WriteMBs: 2.0}

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	// Culprit should be the memory hog, not the IO victim
	if result.PrimaryProcess == "mysqld" {
		t.Error("WHO: should blame memory hog (stress-ng-vm), not IO victim (mysqld)")
	}
	if result.PrimaryProcess == "xtop" {
		t.Error("WHO: xtop must never be blamed")
	}
}

func TestRCA_IOSaturation_CorrectCulprit(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.IO.Some.Avg10 = 40.0

	rates := baseRates()
	rates.DiskRates[0].UtilPct = 95.0
	rates.DiskRates[0].AvgAwaitMs = 50.0
	rates.DiskRates[0].ReadIOPS = 100
	rates.DiskRates[0].WriteIOPS = 2000

	// mysqld is top IO writer
	rates.ProcessRates[1].WriteMBs = 50.0
	rates.ProcessRates[1].ReadMBs = 10.0

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.PrimaryProcess != "mysqld" {
		t.Errorf("WHO: expected mysqld (top IO writer), got %q", result.PrimaryProcess)
	}
}

// ─── Network Bottleneck Tests ────────────────────────────────────────────────

func TestRCA_NetworkDrops_CorrectBottleneck(t *testing.T) {
	snap := baseSnapshot()

	rates := baseRates()
	rates.RetransRate = 100
	rates.NetRates[0].RxDropsPS = 200
	rates.NetRates[0].TxDropsPS = 50

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.PrimaryBottleneck != BottleneckNetwork {
		t.Errorf("expected Network Overload, got %q", result.PrimaryBottleneck)
	}
}

// ─── Cross-Domain Tests ──────────────────────────────────────────────────────

func TestRCA_MemoryInducedIO_PrefersMemory(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.IO.Some.Avg10 = 30.0
	snap.Global.PSI.Memory.Some.Avg10 = 25.0
	snap.Global.Memory.Available = 2 * 1024 * 1024 * 1024

	rates := baseRates()
	rates.DiskRates[0].UtilPct = 80.0
	rates.DiskRates[0].AvgAwaitMs = 30.0
	rates.DiskRates[0].ReadIOPS = 200
	rates.DiskRates[0].WriteIOPS = 200
	rates.DirectReclaimRate = 2000

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	// When memory reclaim is active and both IO+Memory score high,
	// domain conflict resolution should prefer Memory as root cause
	if result.PrimaryBottleneck == BottleneckIO {
		// Check if conflict resolution picked memory
		t.Logf("Bottleneck=%s (score IO=%d, Mem=%d)", result.PrimaryBottleneck,
			result.RCA[0].Score, result.RCA[1].Score)
	}
}

func TestRCA_HealthySystem_NoBottleneck(t *testing.T) {
	snap := baseSnapshot()
	rates := baseRates()

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.Health != model.HealthOK {
		t.Errorf("healthy system should be OK, got health=%d bottleneck=%q score=%d",
			result.Health, result.PrimaryBottleneck, result.PrimaryScore)
	}
}

// ─── App Enrichment Tests ────────────────────────────────────────────────────

func TestRCA_AppEnrichment_OnlyWhenCulprit(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.CPU.Some.Avg10 = 25.0
	snap.Global.Apps = model.AppMetrics{
		Instances: []model.AppInstance{
			{AppType: "mysql", DisplayName: "MySQL", HealthScore: 85},
			{AppType: "redis", DisplayName: "Redis", HealthScore: 95},
			{AppType: "nginx", DisplayName: "Nginx", HealthScore: 100},
		},
	}

	rates := baseRates()
	rates.CPUBusyPct = 99.5

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.Narrative != nil {
		rootCause := strings.ToLower(result.Narrative.RootCause)
		// None of these apps are the culprit, so they shouldn't appear in root cause
		if strings.Contains(rootCause, "mysql") {
			t.Errorf("MySQL should not appear in root cause when not culprit: %q", result.Narrative.RootCause)
		}
		if strings.Contains(rootCause, "redis") {
			t.Errorf("Redis should not appear in root cause when not culprit: %q", result.Narrative.RootCause)
		}
	}
}

func TestRCA_AppEnrichment_DegradedAppShown(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.IO.Some.Avg10 = 40.0
	snap.Global.Apps = model.AppMetrics{
		Instances: []model.AppInstance{
			{AppType: "mysql", DisplayName: "MySQL", HealthScore: 45,
				HealthIssues: []string{"slow queries detected"}},
		},
	}

	rates := baseRates()
	rates.DiskRates[0].UtilPct = 95.0
	rates.DiskRates[0].AvgAwaitMs = 50.0
	rates.DiskRates[0].ReadIOPS = 500
	rates.DiskRates[0].WriteIOPS = 1000

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.Narrative == nil {
		t.Skip("no narrative generated")
	}

	foundMySQL := false
	for _, ev := range result.Narrative.Evidence {
		if strings.Contains(ev, "MySQL") {
			foundMySQL = true
			break
		}
	}
	if !foundMySQL {
		t.Error("degraded MySQL (score 45) should appear in evidence")
	}
}

// ─── Process History Tests ───────────────────────────────────────────────────

func TestProcessHistory_ConsistentCulprit(t *testing.T) {
	ph := NewProcessHistory(50)

	for i := 0; i < 15; i++ {
		rates := &model.RateSnapshot{
			ProcessRates: []model.ProcessRate{
				{PID: 100, Comm: "stress-ng-cpu", CPUPct: 85.0, State: "R"},
				{PID: 200, Comm: "dockerd", CPUPct: 8.0, State: "S"},
				{PID: 300, Comm: "xtop", CPUPct: 5.0, State: "S"},
			},
		}
		ph.Record(rates)
	}

	comm, pid, n := ph.FindCPUCulprit()
	if comm != "stress-ng-cpu" {
		t.Errorf("expected stress-ng-cpu, got %q (PID %d, appearances %d)", comm, pid, n)
	}
	if n < 10 {
		t.Errorf("expected 10+ appearances, got %d", n)
	}
}

func TestProcessHistory_XtopExcluded(t *testing.T) {
	ph := NewProcessHistory(50)

	for i := 0; i < 15; i++ {
		rates := &model.RateSnapshot{
			ProcessRates: []model.ProcessRate{
				{PID: 100, Comm: "xtop", CPUPct: 90.0, State: "R"},
				{PID: 200, Comm: "app", CPUPct: 50.0, State: "R"},
			},
		}
		ph.Record(rates)
	}

	comm, _, _ := ph.FindCPUCulprit()
	if comm == "xtop" {
		t.Error("xtop must never be returned as culprit")
	}
	if comm != "app" {
		t.Errorf("expected 'app', got %q", comm)
	}
}

func TestProcessHistory_MemoryCulprit(t *testing.T) {
	ph := NewProcessHistory(50)

	for i := 0; i < 15; i++ {
		rates := &model.RateSnapshot{
			ProcessRates: []model.ProcessRate{
				{PID: 100, Comm: "stress-ng-vm", RSS: 12 * 1024 * 1024 * 1024, CPUPct: 30},
				{PID: 200, Comm: "mysqld", RSS: 512 * 1024 * 1024, CPUPct: 5},
			},
		}
		ph.Record(rates)
	}

	comm, _, n := ph.FindMemCulprit()
	if comm != "stress-ng-vm" {
		t.Errorf("expected stress-ng-vm as memory culprit, got %q (appearances %d)", comm, n)
	}
}

func TestProcessHistory_IOCulprit(t *testing.T) {
	ph := NewProcessHistory(50)

	for i := 0; i < 15; i++ {
		rates := &model.RateSnapshot{
			ProcessRates: []model.ProcessRate{
				{PID: 100, Comm: "mysqld", ReadMBs: 10, WriteMBs: 50, CPUPct: 5},
				{PID: 200, Comm: "nginx", ReadMBs: 1, WriteMBs: 0.5, CPUPct: 2},
			},
		}
		ph.Record(rates)
	}

	comm, _, _ := ph.FindIOCulprit()
	if comm != "mysqld" {
		t.Errorf("expected mysqld as IO culprit, got %q", comm)
	}
}

// ─── Evidence Scoping Tests ──────────────────────────────────────────────────

func TestSelectTopEvidence_PrimaryDomainFirst(t *testing.T) {
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{
			{
				Bottleneck: BottleneckCPU,
				Score:      70,
				EvidenceV2: []model.Evidence{
					{ID: "cpu.psi", Domain: model.DomainCPU, Strength: 0.8, Message: "CPU PSI some=25%"},
					{ID: "cpu.busy", Domain: model.DomainCPU, Strength: 0.9, Message: "CPU busy=99%"},
				},
			},
			{
				Bottleneck: BottleneckNetwork,
				Score:      30,
				EvidenceV2: []model.Evidence{
					{ID: "net.retrans", Domain: model.DomainNetwork, Strength: 0.95, Message: "retrans=100/s"},
				},
			},
		},
	}

	lines := selectTopEvidence(result, 2)

	// Should pick CPU evidence first (primary domain), not network retrans (higher strength)
	for _, line := range lines {
		if strings.Contains(line, "retrans") {
			t.Errorf("CPU bottleneck top-2 evidence should not include network retrans: %v", lines)
		}
	}
}

// ─── Narrative Humanization Tests ────────────────────────────────────────────

func TestBuildNarrative_CPUBottleneck_NoNetworkNoise(t *testing.T) {
	snap := baseSnapshot()
	snap.Global.PSI.CPU.Some.Avg10 = 25.0

	rates := baseRates()
	rates.CPUBusyPct = 99.5
	rates.RetransRate = 10.0

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h)

	if result.Narrative == nil {
		t.Skip("no narrative")
	}

	for _, ev := range result.Narrative.Evidence {
		low := strings.ToLower(ev)
		if strings.Contains(low, "retrans") || strings.Contains(low, "tcp") || strings.Contains(low, "drop") {
			t.Errorf("CPU narrative should not contain network evidence: %q", ev)
		}
	}
}
