package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

func TestDetectHiddenLatencyV2_NoSchedstat(t *testing.T) {
	// On systems without /proc/schedstat, should fall back gracefully
	curr := &model.Snapshot{
		Global: model.GlobalMetrics{
			CPU: model.CPUMetrics{NumCPUs: 4},
		},
	}
	rates := &model.RateSnapshot{
		CPUBusyPct: 50,
	}
	result := &model.AnalysisResult{}

	DetectHiddenLatencyV2(curr, rates, result)
	// Should not panic; may or may not set hidden latency depending on system
}

func TestDetectHiddenLatencyV2_HighSchedulerWait(t *testing.T) {
	// This test verifies the structure works; on real systems /proc/schedstat
	// will be read. We can't easily mock the file read without build tags.
	curr := &model.Snapshot{
		Global: model.GlobalMetrics{
			CPU: model.CPUMetrics{NumCPUs: 4},
		},
	}
	rates := &model.RateSnapshot{
		CPUBusyPct: 70,
	}
	result := &model.AnalysisResult{}

	// Just verify it doesn't panic
	DetectHiddenLatencyV2(curr, rates, result)
}

func TestReadSchedDebug(t *testing.T) {
	// Should return defaults or actual values without panicking
	lat, gran, wake := readSchedDebug()
	if lat <= 0 {
		t.Errorf("expected positive latency target, got %d", lat)
	}
	if gran <= 0 {
		t.Errorf("expected positive min granularity, got %d", gran)
	}
	if wake <= 0 {
		t.Errorf("expected positive wakeup granularity, got %d", wake)
	}
	t.Logf("sched debug: latency=%dms gran=%dms wake=%dms", lat, gran, wake)
}
