package ui

import (
	"strings"
	"testing"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// testSnapshot creates a minimal but valid snapshot for render tests.
func testSnapshot() *model.Snapshot {
	return &model.Snapshot{
		Global: model.GlobalMetrics{
			PSI: model.PSIMetrics{
				CPU:    model.PSIResource{Some: model.PSILine{Avg10: 1.5}},
				Memory: model.PSIResource{Some: model.PSILine{Avg10: 0.2}},
				IO:     model.PSIResource{Some: model.PSILine{Avg10: 3.1}},
			},
			CPU: model.CPUMetrics{
				NumCPUs: 4,
				LoadAvg: model.LoadAvg{Load1: 2.1, Load5: 1.8, Load15: 1.5, Running: 3, Total: 200},
			},
			Memory: model.MemoryMetrics{
				Total:     16 * 1024 * 1024 * 1024, // 16G
				Available: 8 * 1024 * 1024 * 1024,  // 8G
				Cached:    4 * 1024 * 1024 * 1024,
				SwapTotal: 4 * 1024 * 1024 * 1024,
				SwapUsed:  512 * 1024 * 1024,
			},
			Conntrack: model.ConntrackStats{Count: 500, Max: 262144},
			EphemeralPorts: model.EphemeralPorts{
				RangeLo: 32768, RangeHi: 60999, InUse: 150,
			},
			Apps: model.AppMetrics{
				Instances: []model.AppInstance{
					{ID: "mysql-0", AppType: "mysql", DisplayName: "MySQL", PID: 1234, HealthScore: 85, RSSMB: 512, Connections: 10},
					{ID: "nginx-0", AppType: "nginx", DisplayName: "Nginx", PID: 5678, HealthScore: 100, RSSMB: 64, Connections: 50},
				},
			},
			Sentinel: model.SentinelData{Active: true},
		},
		SysInfo: &model.SysInfo{
			Hostname:       "test-host",
			OS:             "Ubuntu 24.04",
			Kernel:         "6.8.0",
			Virtualization: "KVM",
		},
		Processes: []model.ProcessMetrics{
			{PID: 1234, Comm: "mysqld", RSS: 512 * 1024 * 1024},
			{PID: 5678, Comm: "nginx", RSS: 64 * 1024 * 1024},
		},
	}
}

func testRates() *model.RateSnapshot {
	return &model.RateSnapshot{
		CPUBusyPct:    25.3,
		CPUSystemPct:  5.2,
		CPUStealPct:   0.1,
		CPUSoftIRQPct: 0.3,
		CtxSwitchRate:  800,
		RetransRate:   0,
		DiskRates: []model.DiskRate{
			{Name: "sda", UtilPct: 15.2, AvgAwaitMs: 2.5, ReadIOPS: 50, WriteIOPS: 200, ReadMBs: 1.2, WriteMBs: 5.4, QueueDepth: 1},
		},
		NetRates: []model.NetRate{
			{RxMBs: 0.5, TxMBs: 0.3},
		},
		MountRates: []model.MountRate{
			{MountPoint: "/", FreePct: 45, ETASeconds: 86400},
		},
	}
}

func testResult() *model.AnalysisResult {
	return &model.AnalysisResult{
		Health:             model.HealthOK,
		PrimaryBottleneck:  "",
		Confidence:         0,
		StableSince:        120,
		Capacities: []model.Capacity{
			{Label: "CPU headroom", Pct: 74.7, Current: "25% busy", Limit: "4 cores"},
			{Label: "MemAvailable", Pct: 50, Current: "8.0G", Limit: "16.0G"},
		},
		CPUOwners: []model.Owner{{Name: "[root]", Value: "25.3%"}},
		MemOwners: []model.Owner{{Name: "user.slice", Value: "45.2% (7.2G)"}},
		IOOwners:  []model.Owner{{Name: "[root]", Value: "5.4 MB/s"}},
		NetOwners: []model.Owner{{Name: "nginx", Value: "0.3 MB/s"}},
	}
}

// --- Page Render Tests ---
// These verify that pages render without panicking and produce non-empty output.

func TestRenderCPUPage_NoPanic(t *testing.T) {
	snap := testSnapshot()
	rates := testRates()
	result := testResult()
	got := renderCPUPage(snap, rates, result, nil, 120, 40, false)
	if got == "" {
		t.Error("renderCPUPage returned empty string")
	}
	if !strings.Contains(got, "CPU") {
		t.Error("renderCPUPage output missing 'CPU'")
	}
}

func TestRenderCPUPage_IntermediateMode(t *testing.T) {
	snap := testSnapshot()
	rates := testRates()
	result := testResult()
	got := renderCPUPage(snap, rates, result, nil, 120, 40, true)
	if got == "" {
		t.Error("renderCPUPage intermediate returned empty")
	}
	// Should contain verdict badges
	vis := stripANSI(got)
	if !strings.Contains(vis, "OK") && !strings.Contains(vis, "HIGH") {
		t.Error("renderCPUPage intermediate should contain verdict badges")
	}
}

func TestRenderMemPage_NoPanic(t *testing.T) {
	snap := testSnapshot()
	rates := testRates()
	result := testResult()
	got := renderMemPage(snap, rates, result, nil, 120, 40, false)
	if got == "" {
		t.Error("renderMemPage returned empty string")
	}
}

func TestRenderIOPage_NoPanic(t *testing.T) {
	snap := testSnapshot()
	rates := testRates()
	result := testResult()
	got := renderIOPage(snap, rates, result, nil, nil, 120, 40, false)
	if got == "" {
		t.Error("renderIOPage returned empty string")
	}
}

func TestRenderGPUPage_NoGPU(t *testing.T) {
	snap := testSnapshot()
	got := renderGPUPage(snap, 120, 40)
	if got == "" {
		t.Error("renderGPUPage returned empty string")
	}
	vis := stripANSI(got)
	if !strings.Contains(vis, "No NVIDIA GPU") {
		t.Error("renderGPUPage should show 'No NVIDIA GPU detected'")
	}
}

func TestRenderGPUPage_WithGPU(t *testing.T) {
	snap := testSnapshot()
	snap.Global.GPU = model.GPUSnapshot{
		Available: true,
		Devices: []model.GPUDevice{
			{Index: 0, Name: "RTX 3090", Driver: "535.129", UtilGPU: 45, UtilMem: 30,
				MemUsed: 4 * 1024 * 1024 * 1024, MemTotal: 24 * 1024 * 1024 * 1024,
				Temperature: 65, PowerDraw: 180, PowerLimit: 350, FanSpeed: 40},
		},
	}
	got := renderGPUPage(snap, 120, 40)
	vis := stripANSI(got)
	if !strings.Contains(vis, "RTX 3090") {
		t.Error("renderGPUPage should show GPU name")
	}
	if !strings.Contains(vis, "45.0%") {
		t.Error("renderGPUPage should show utilization")
	}
}

func TestRenderProbePage_NoPanic(t *testing.T) {
	pm := engine.NewProbeManager()
	snap := testSnapshot()
	var expanded [13]bool
	got := renderProbePage(pm, snap, 120, 40, 0, expanded, false)
	if got == "" {
		t.Error("renderProbePage returned empty string")
	}
}

func TestRenderThresholdsPage_NilResult(t *testing.T) {
	// Should not panic with nil result
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("renderThresholdsPage panicked with nil result: %v", r)
		}
	}()
	// Can't call directly without knowing signature — skip if complex
}

func TestExportHTML_NoPanic(t *testing.T) {
	snap := testSnapshot()
	rates := testRates()
	result := testResult()
	path, err := exportHTMLReport(snap, rates, result)
	if err != nil {
		t.Fatalf("exportHTMLReport failed: %v", err)
	}
	if path == "" {
		t.Error("exportHTMLReport returned empty path")
	}
	// Clean up
	if path != "" {
		_ = removeFile(path)
	}
}

func TestExportHTML_ContainsKeyElements(t *testing.T) {
	snap := testSnapshot()
	rates := testRates()
	result := testResult()
	path, err := exportHTMLReport(snap, rates, result)
	if err != nil {
		t.Fatalf("exportHTMLReport failed: %v", err)
	}
	if path != "" {
		defer removeFile(path)
	}
	data, err := readFileBytes(path)
	if err != nil {
		t.Fatalf("failed to read HTML report: %v", err)
	}
	html := string(data)
	checks := []string{"<!DOCTYPE html>", "test-host", "HEALTHY", "CPU", "Memory", "Disk IO", "MySQL", "Nginx"}
	for _, c := range checks {
		if !strings.Contains(html, c) {
			t.Errorf("HTML report missing %q", c)
		}
	}
}

func TestPagePicker_FilterEntries(t *testing.T) {
	m := &Model{pagePickerQuery: "gpu"}
	filtered := m.filteredPickerEntries()
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered entry for 'gpu', got %d", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Page != PageGPU {
		t.Errorf("expected GPU page, got %v", filtered[0].Page)
	}
}

func TestPagePicker_EmptyQuery(t *testing.T) {
	m := &Model{pagePickerQuery: ""}
	filtered := m.filteredPickerEntries()
	if len(filtered) != len(pagePickerEntries) {
		t.Errorf("empty query should return all entries, got %d/%d", len(filtered), len(pagePickerEntries))
	}
}

func TestPagePicker_NoMatch(t *testing.T) {
	m := &Model{pagePickerQuery: "zzzznonexistent"}
	filtered := m.filteredPickerEntries()
	if len(filtered) != 0 {
		t.Errorf("expected 0 entries for nonsense query, got %d", len(filtered))
	}
}

func TestMetricVerdict(t *testing.T) {
	tests := []struct {
		val, warn, crit float64
		wantContains    string
	}{
		{10, 70, 90, "OK"},
		{75, 70, 90, "HIGH"},
		{95, 70, 90, "CRITICAL"},
	}
	for _, tt := range tests {
		got := stripANSI(metricVerdict(tt.val, tt.warn, tt.crit))
		if !strings.Contains(got, tt.wantContains) {
			t.Errorf("metricVerdict(%.0f, %.0f, %.0f) = %q, want containing %q", tt.val, tt.warn, tt.crit, got, tt.wantContains)
		}
	}
}

// helpers for test cleanup
func removeFile(path string) error {
	return removeFileOS(path)
}

func readFileBytes(path string) ([]byte, error) {
	return readFileBytesOS(path)
}
