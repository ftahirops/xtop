//go:build linux

package configdrift_test

import (
	"os"
	"testing"

	"github.com/ftahirops/xtop/collector/configdrift"
)

func TestSnapshotSmoke(t *testing.T) {
	// vm.swappiness almost always exists; skip the test if it doesn't
	// (minimal container or unusual kernel).
	if _, err := os.Stat("/proc/sys/vm/swappiness"); os.IsNotExist(err) {
		t.Skip("/proc/sys/vm/swappiness not present — skipping smoke test")
	}

	m, err := configdrift.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error: %v", err)
	}
	if len(m) == 0 {
		t.Fatal("Snapshot() returned empty map on a Linux host")
	}

	if val, ok := m["vm.swappiness"]; !ok || val == "" {
		t.Errorf("expected vm.swappiness in snapshot, got map=%v", m)
	}

	// Every value in the map must have a non-empty key.
	for k, v := range m {
		if k == "" {
			t.Error("snapshot contains empty key")
		}
		if v == "" {
			t.Errorf("snapshot key %q has empty value", k)
		}
	}
}
