//go:build linux

package configdrift_test

// snapshot_smoke_test.go — P4.6: real read-path smoke test for configdrift.Snapshot.
//
// Calls the REAL Snapshot() on this host and asserts:
//   - The returned map is non-nil
//   - At least one key is present (typically vm.swappiness on any Linux host)
//   - Every present value is non-empty (no empty strings in the map)
//   - The call does not error
//
// This test proves the actual /proc/sys read path works without writing anything.
// It is gated on //go:build linux and is read-only by construction (Snapshot
// uses os.ReadFile only; enforced by TestSuggestedRemediationNoWrite).

import (
	"os"
	"testing"

	"github.com/ftahirops/xtop/collector/configdrift"
)

// TestConfigDriftSnapshotSmoke calls the real Snapshot() on this Linux host.
// Skips gracefully if /proc/sys/vm/swappiness does not exist (minimal container).
func TestConfigDriftSnapshotSmoke(t *testing.T) {
	// Gate: if the most common sysctl path is absent this is an unusual environment.
	if _, err := os.Stat("/proc/sys/vm/swappiness"); os.IsNotExist(err) {
		t.Skip("/proc/sys/vm/swappiness not present — skipping smoke test on this host")
	}

	m, err := configdrift.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() returned unexpected error: %v", err)
	}

	// The map must be non-nil and non-empty on a normal Linux host.
	if m == nil {
		t.Fatal("Snapshot() returned nil map")
	}
	if len(m) == 0 {
		t.Fatal("Snapshot() returned empty map on a Linux host with /proc/sys present")
	}

	// vm.swappiness should be present and non-empty on every standard Linux host.
	if val, ok := m["vm.swappiness"]; !ok {
		t.Errorf("expected vm.swappiness in snapshot; map keys: %v", keys(m))
	} else if val == "" {
		t.Error("vm.swappiness value is empty — Parse() should return a non-empty string")
	}

	// Every value in the returned map must be non-empty — Snapshot skips empties.
	for k, v := range m {
		if k == "" {
			t.Error("snapshot contains an empty key")
		}
		if v == "" {
			t.Errorf("snapshot key %q has empty value — Snapshot should skip blank reads", k)
		}
	}

	t.Logf("Snapshot() returned %d keys (read-only, no writes)", len(m))
}

// keys returns the key names from a map for use in error messages.
func keys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
