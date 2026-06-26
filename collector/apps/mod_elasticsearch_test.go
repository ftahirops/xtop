package apps

import (
	"strings"
	"testing"

	"github.com/ftahirops/xtop/model"
)

// ────────────────────────────────────────────────────────────────────────────
// esApplyHealthRules tests
// ────────────────────────────────────────────────────────────────────────────

// newESInst creates a fresh AppInstance with HasDeepMetrics=true and the given
// DeepMetrics map. HealthScore starts at 100 (the engine convention).
func newESInst(dm map[string]string) *model.AppInstance {
	inst := &model.AppInstance{
		HasDeepMetrics: true,
		DeepMetrics:    dm,
		HealthScore:    100,
	}
	return inst
}

func TestESApplyHealthRules_greenCluster(t *testing.T) {
	inst := newESInst(map[string]string{
		"status":            "green",
		"unassigned_shards": "0",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 100 {
		t.Errorf("green cluster: HealthScore = %d, want 100", inst.HealthScore)
	}
	if len(inst.HealthIssues) != 0 {
		t.Errorf("green cluster: unexpected issues: %v", inst.HealthIssues)
	}
}

func TestESApplyHealthRules_redCluster(t *testing.T) {
	inst := newESInst(map[string]string{
		"status": "red",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore > 70 {
		t.Errorf("red cluster: HealthScore = %d, want ≤70", inst.HealthScore)
	}
	if !anyContains(inst.HealthIssues, "RED") {
		t.Error("red cluster: expected 'RED' issue")
	}
}

func TestESApplyHealthRules_yellowCluster(t *testing.T) {
	inst := newESInst(map[string]string{
		"status": "yellow",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 90 {
		t.Errorf("yellow cluster: HealthScore = %d, want 90", inst.HealthScore)
	}
	if !anyContains(inst.HealthIssues, "YELLOW") {
		t.Error("yellow cluster: expected 'YELLOW' issue")
	}
}

func TestESApplyHealthRules_unassignedShards(t *testing.T) {
	inst := newESInst(map[string]string{
		"status":            "green",
		"unassigned_shards": "5",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 90 {
		t.Errorf("unassigned shards: HealthScore = %d, want 90", inst.HealthScore)
	}
	if !anyContains(inst.HealthIssues, "unassigned") {
		t.Error("expected 'unassigned' issue")
	}
}

func TestESApplyHealthRules_jvmHeapCritical(t *testing.T) {
	inst := newESInst(map[string]string{
		"jvm_heap_used_pct": "92%",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 75 {
		t.Errorf("JVM heap >90%%: HealthScore = %d, want 75", inst.HealthScore)
	}
	if !anyContains(inst.HealthIssues, "JVM heap") {
		t.Error("expected JVM heap issue")
	}
}

func TestESApplyHealthRules_jvmHeapWarning(t *testing.T) {
	inst := newESInst(map[string]string{
		"jvm_heap_used_pct": "87%",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 85 {
		t.Errorf("JVM heap 85-90%%: HealthScore = %d, want 85", inst.HealthScore)
	}
}

func TestESApplyHealthRules_fielddataEvictions(t *testing.T) {
	inst := newESInst(map[string]string{
		"fielddata_evictions": "500",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 90 {
		t.Errorf("fielddata evictions: HealthScore = %d, want 90", inst.HealthScore)
	}
	if !anyContains(inst.HealthIssues, "fielddata") {
		t.Error("expected fielddata evictions issue")
	}
}

func TestESApplyHealthRules_circuitBreakerTrips(t *testing.T) {
	inst := newESInst(map[string]string{
		"cb_total_tripped":    "3",
		"cb_fielddata_tripped": "3",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 80 {
		t.Errorf("circuit breaker: HealthScore = %d, want 80", inst.HealthScore)
	}
	if !anyContains(inst.HealthIssues, "circuit breaker") {
		t.Error("expected circuit breaker issue")
	}
}

func TestESApplyHealthRules_threadPoolRejections(t *testing.T) {
	inst := newESInst(map[string]string{
		"tp_total_rejected": "10",
		"tp_write_rejected": "10",
	})
	esApplyHealthRules(inst)
	if inst.HealthScore != 85 {
		t.Errorf("thread pool: HealthScore = %d, want 85", inst.HealthScore)
	}
	if !anyContains(inst.HealthIssues, "thread-pool") {
		t.Error("expected thread-pool rejections issue")
	}
}

func TestESApplyHealthRules_noDeepMetrics(t *testing.T) {
	inst := &model.AppInstance{
		HasDeepMetrics: false,
		DeepMetrics:    map[string]string{"status": "red"},
		HealthScore:    100,
	}
	esApplyHealthRules(inst)
	// Should short-circuit and leave score unchanged
	if inst.HealthScore != 100 {
		t.Errorf("no deep metrics: HealthScore = %d, want 100 (no-op)", inst.HealthScore)
	}
}

func TestESApplyHealthRules_malformed(t *testing.T) {
	cases := []struct {
		name string
		dm   map[string]string
	}{
		{"nil map", nil},
		{"empty map", map[string]string{}},
		{"non-numeric unassigned_shards", map[string]string{"unassigned_shards": "notanumber"}},
		{"non-numeric jvm", map[string]string{"jvm_heap_used_pct": "abc%"}},
		{"non-numeric cb_total_tripped", map[string]string{"cb_total_tripped": "NaN"}},
		{"empty status", map[string]string{"status": ""}},
		{"unknown status", map[string]string{"status": "banana"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inst := &model.AppInstance{
				HasDeepMetrics: true,
				DeepMetrics:    c.dm,
				HealthScore:    100,
			}
			// Must not panic
			esApplyHealthRules(inst)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// fmtLargeNum tests
// ────────────────────────────────────────────────────────────────────────────

func TestFmtLargeNum(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
	}{
		{float64(0), "0"},
		{float64(999), "999"},
		{float64(1000), "1.0K"},
		{float64(1_500_000), "1.5M"},
		{float64(2_000_000_000), "2.0B"},
		{"stringval", "stringval"}, // non-numeric falls through to %v
	}
	for _, c := range cases {
		got := fmtLargeNum(c.in)
		if got != c.want {
			t.Errorf("fmtLargeNum(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// fmtBytes (ES variant) tests
// ────────────────────────────────────────────────────────────────────────────

func TestFmtBytes(t *testing.T) {
	// Test happy-path cases with exact value assertions.
	// fmtBytes thresholds: >=1e12 TB, >=1e9 GB, >=1e6 MB, >=1e3 KB, else B.
	// Format: "%.1f <unit>" for KB/MB/GB/TB; "%.0f B" for bytes.
	cases := []struct {
		in   interface{}
		want string
	}{
		{float64(0), "0 B"},
		{float64(500), "500 B"},
		{float64(1000), "1.0 KB"},
		{float64(1500), "1.5 KB"},
		{float64(1_000_000), "1.0 MB"},
		{float64(2_500_000), "2.5 MB"},
		{float64(1_000_000_000), "1.0 GB"},
		{float64(5_500_000_000), "5.5 GB"},
		{float64(1_000_000_000_000), "1.0 TB"},
		{float64(2_500_000_000_000), "2.5 TB"},
	}
	for _, c := range cases {
		got := fmtBytes(c.in)
		if got != c.want {
			t.Errorf("fmtBytes(%v) = %q, want %q", c.in, got, c.want)
		}
	}

	// Test malformed/edge cases: must not panic, must produce non-empty strings.
	edgeCases := []interface{}{"notanumber", nil, float64(-1), float64(1e15)}
	for _, v := range edgeCases {
		got := fmtBytes(v)
		if got == "" {
			t.Errorf("fmtBytes(%v) returned empty string", v)
		}
	}
}

func TestFmtBytesScaling(t *testing.T) {
	// TB
	if s := fmtBytes(float64(2e12)); !strings.Contains(s, "TB") {
		t.Errorf("fmtBytes(2TB) = %q, expected 'TB'", s)
	}
	// GB
	if s := fmtBytes(float64(3e9)); !strings.Contains(s, "GB") {
		t.Errorf("fmtBytes(3GB) = %q, expected 'GB'", s)
	}
	// MB
	if s := fmtBytes(float64(5e6)); !strings.Contains(s, "MB") {
		t.Errorf("fmtBytes(5MB) = %q, expected 'MB'", s)
	}
	// KB
	if s := fmtBytes(float64(2e3)); !strings.Contains(s, "KB") {
		t.Errorf("fmtBytes(2KB) = %q, expected 'KB'", s)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

func anyContains(strs []string, sub string) bool {
	for _, s := range strs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
