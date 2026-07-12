//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestIOCulpritIgnoresNegligibleSwap reproduces the culprit misattribution:
// the memory-hog branch fired on ANY swap-in > 0, so a trace of swap made it
// blame the top-RSS process instead of the actual heavy IO writer.
func TestIOCulpritIgnoresNegligibleSwap(t *testing.T) {
	rates := &model.RateSnapshot{
		SwapInRate: 0.01, // negligible
		ProcessRates: []model.ProcessRate{
			{Comm: "db-writer", PID: 10, WriteMBs: 50, RSS: 100 << 20},
			{Comm: "cache-hog", PID: 20, WriteMBs: 0, RSS: 8 << 30},
		},
	}
	r := &model.RCAEntry{Bottleneck: BottleneckIO}
	findIOCulprit(&model.Snapshot{}, rates, r)

	if r.TopProcess != "db-writer" {
		t.Fatalf("negligible swap misattributed IO culprit to %q; want the real writer db-writer", r.TopProcess)
	}
}

// TestIOCulpritRealSwapBlamesMemoryHog guards the real case: with genuine swap
// activity the memory hog IS the cause of the IO.
func TestIOCulpritRealSwapBlamesMemoryHog(t *testing.T) {
	rates := &model.RateSnapshot{
		SwapInRate: 8, // real swap storm
		ProcessRates: []model.ProcessRate{
			{Comm: "db-writer", PID: 10, WriteMBs: 50, RSS: 100 << 20},
			{Comm: "cache-hog", PID: 20, WriteMBs: 0, RSS: 8 << 30},
		},
	}
	r := &model.RCAEntry{Bottleneck: BottleneckIO}
	findIOCulprit(&model.Snapshot{}, rates, r)

	if r.TopProcess != "cache-hog" {
		t.Fatalf("real swap storm should blame the memory hog cache-hog, got %q", r.TopProcess)
	}
}
