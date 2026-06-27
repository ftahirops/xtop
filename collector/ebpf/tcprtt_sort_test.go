//go:build 386 || amd64

package ebpf

import (
	"math"
	"sort"
	"testing"
)

// tcprttAvg computes the average RTT from an entry, treating Count==0 as 0.
// This mirrors the sort comparator logic in runner.go.
func tcprttAvg(e TCPRTTResult) float64 {
	if e.Count == 0 {
		return 0
	}
	return float64(e.SumUs) / float64(e.Count)
}

// TestTCPRTTSortCountZeroNoNaN verifies that sorting a slice of TCPRTTResult
// entries that includes Count==0 entries does not produce NaN comparisons or
// an undefined sort order.
func TestTCPRTTSortCountZeroNoNaN(t *testing.T) {
	entries := []TCPRTTResult{
		{DstStr: "10.0.0.1:443", SumUs: 1000, Count: 10},  // avg=100
		{DstStr: "10.0.0.2:80", SumUs: 0, Count: 0},       // Count==0 — was a NaN source
		{DstStr: "10.0.0.3:8080", SumUs: 500, Count: 5},   // avg=100
		{DstStr: "10.0.0.4:5432", SumUs: 2000, Count: 4},  // avg=500
	}

	// Verify no NaN from tcprttAvg
	for _, e := range entries {
		avg := tcprttAvg(e)
		if math.IsNaN(avg) || math.IsInf(avg, 0) {
			t.Errorf("tcprttAvg(%q) = %v, want finite value", e.DstStr, avg)
		}
	}

	// Apply the same sort logic as the domain-mode path in runner.go.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == 0 || entries[j].Count == 0 {
			return entries[i].Count > entries[j].Count
		}
		avgI := float64(entries[i].SumUs) / float64(entries[i].Count)
		avgJ := float64(entries[j].SumUs) / float64(entries[j].Count)
		return avgI > avgJ
	})

	// Verify the zero-count entry sorted to the end (or at least not first).
	if entries[0].Count == 0 {
		t.Errorf("Count==0 entry sorted to position 0; expected a non-zero entry first")
	}

	// Verify the highest average (500) is first.
	if entries[0].DstStr != "10.0.0.4:5432" {
		t.Errorf("expected highest-avg entry first, got %q", entries[0].DstStr)
	}

	// Verify the zero-count entry is last.
	last := entries[len(entries)-1]
	if last.Count != 0 {
		t.Errorf("expected Count==0 entry last, got Count=%d DstStr=%q", last.Count, last.DstStr)
	}
}
