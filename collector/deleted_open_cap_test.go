package collector

import (
	"testing"
)

// TestDeletedOpenMaxPIDsCap verifies that the PID scan cap was raised from the
// original 50 to at least 1024, ensuring long-running daemons with high PIDs
// are not silently skipped (M-A fix).  The actual value is deletedOpenMaxPIDs.
func TestDeletedOpenMaxPIDsCap(t *testing.T) {
	const wantMinCap = 1024 // original cap was 50; 4096 is the new value
	if deletedOpenMaxPIDs < wantMinCap {
		t.Errorf("deletedOpenMaxPIDs = %d; want >= %d (original cap of 50 was too low, daemons with high PIDs were silently missed)", deletedOpenMaxPIDs, wantMinCap)
	}
}
