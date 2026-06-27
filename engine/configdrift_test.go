package engine

import (
	"strings"
	"testing"
	"time"
)

// TestParamDrift_ChangeDetectedAsDrift verifies the core drift case:
// a key present in the baseline with a different live value → one SystemChange
// with Type="config_drift_memory" and Detail containing the old→new transition.
func TestParamDrift_ChangeDetectedAsDrift(t *testing.T) {
	baseline := []ConfigBaselineRecord{
		{Key: "vm.swappiness", Value: "10", Domain: "memory", FirstSeen: time.Now(), Acked: false},
	}
	d := NewParamDriftDetector(baseline)

	live := map[string]string{"vm.swappiness": "60"}
	changes, newBaselines := d.Detect(live, time.Now())

	if len(changes) != 1 {
		t.Fatalf("expected 1 drift change, got %d: %+v", len(changes), changes)
	}
	if changes[0].Type != "config_drift_memory" {
		t.Errorf("expected Type=config_drift_memory, got %q", changes[0].Type)
	}
	if !strings.Contains(changes[0].Detail, "vm.swappiness") {
		t.Errorf("Detail should contain key name, got %q", changes[0].Detail)
	}
	if !strings.Contains(changes[0].Detail, "10") || !strings.Contains(changes[0].Detail, "60") {
		t.Errorf("Detail should contain old→new values, got %q", changes[0].Detail)
	}
	if len(newBaselines) != 0 {
		t.Errorf("expected no newBaselines for drift case, got %d", len(newBaselines))
	}
}

// TestParamDrift_FirstSeenKeyBecomesBaseline verifies that a key absent from
// the baseline is NOT emitted as drift — it is returned as a new baseline entry.
func TestParamDrift_FirstSeenKeyBecomesBaseline(t *testing.T) {
	d := NewParamDriftDetector(nil) // empty baseline

	live := map[string]string{"vm.swappiness": "10"}
	changes, newBaselines := d.Detect(live, time.Now())

	if len(changes) != 0 {
		t.Fatalf("first-seen key must not produce drift, got %d changes: %+v", len(changes), changes)
	}
	if len(newBaselines) != 1 {
		t.Fatalf("expected 1 newBaseline entry, got %d", len(newBaselines))
	}
	nb := newBaselines[0]
	if nb.Key != "vm.swappiness" {
		t.Errorf("newBaseline Key should be vm.swappiness, got %q", nb.Key)
	}
	if nb.Value != "10" {
		t.Errorf("newBaseline Value should be 10, got %q", nb.Value)
	}
	if nb.Domain != "memory" {
		t.Errorf("newBaseline Domain should be memory (from Keys registry), got %q", nb.Domain)
	}
	if nb.Acked {
		t.Error("first-seen baseline should not be acked")
	}
}

// TestParamDrift_NoChangeWhenEqual verifies that no changes or new baselines
// are produced when the live value matches the baseline value.
func TestParamDrift_NoChangeWhenEqual(t *testing.T) {
	baseline := []ConfigBaselineRecord{
		{Key: "vm.swappiness", Value: "60", Domain: "memory", FirstSeen: time.Now()},
	}
	d := NewParamDriftDetector(baseline)

	live := map[string]string{"vm.swappiness": "60"}
	changes, newBaselines := d.Detect(live, time.Now())

	if len(changes) != 0 {
		t.Errorf("expected no changes when live==baseline, got %d: %+v", len(changes), changes)
	}
	if len(newBaselines) != 0 {
		t.Errorf("expected no newBaselines when live==baseline, got %d", len(newBaselines))
	}
}

// TestParamDrift_AbsentKeyIgnored verifies that a key present in the baseline
// but absent from the live snapshot does NOT produce a drift event.
// (Kernel module not loaded, VM without cpufreq, etc. — treat as "unknown".)
func TestParamDrift_AbsentKeyIgnored(t *testing.T) {
	baseline := []ConfigBaselineRecord{
		{Key: "cpu.governor", Value: "performance", Domain: "cpu", FirstSeen: time.Now()},
	}
	d := NewParamDriftDetector(baseline)

	live := map[string]string{} // cpu.governor absent
	changes, newBaselines := d.Detect(live, time.Now())

	if len(changes) != 0 {
		t.Errorf("absent live key must not produce drift, got %d: %+v", len(changes), changes)
	}
	if len(newBaselines) != 0 {
		t.Errorf("absent live key must not produce newBaseline, got %d", len(newBaselines))
	}
}

// TestParamDrift_DomainSetOnChange verifies the Domain field on SystemChange is
// set correctly (maps to the configdrift.Keys registry domain).
func TestParamDrift_DomainSetOnChange(t *testing.T) {
	baseline := []ConfigBaselineRecord{
		{Key: "net.core.somaxconn", Value: "128", Domain: "network", FirstSeen: time.Now()},
	}
	d := NewParamDriftDetector(baseline)

	live := map[string]string{"net.core.somaxconn": "4096"}
	changes, _ := d.Detect(live, time.Now())

	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Type != "config_drift_network" {
		t.Errorf("expected config_drift_network, got %q", changes[0].Type)
	}
	if changes[0].Domain != "network" {
		t.Errorf("expected Domain=network, got %q", changes[0].Domain)
	}
}

// TestParamDrift_BaselineNotMutatedOnDrift verifies that repeated calls to
// Detect keep emitting drift (baseline is not auto-updated on change).
func TestParamDrift_BaselineNotMutatedOnDrift(t *testing.T) {
	baseline := []ConfigBaselineRecord{
		{Key: "vm.swappiness", Value: "10", Domain: "memory", FirstSeen: time.Now()},
	}
	d := NewParamDriftDetector(baseline)
	live := map[string]string{"vm.swappiness": "60"}

	changes1, _ := d.Detect(live, time.Now())
	changes2, _ := d.Detect(live, time.Now())

	if len(changes1) != 1 || len(changes2) != 1 {
		t.Errorf("drift should re-emit on every Detect call; got %d, %d", len(changes1), len(changes2))
	}
}

// TestParamDrift_UnknownKeyFirstSeen covers a key not in configdrift.Keys
// registry — domain falls back to "unknown", no panic.
func TestParamDrift_UnknownKeyFirstSeen(t *testing.T) {
	d := NewParamDriftDetector(nil)
	live := map[string]string{"some.unknown.param": "42"}
	changes, newBaselines := d.Detect(live, time.Now())

	if len(changes) != 0 {
		t.Errorf("unknown first-seen key should not produce drift")
	}
	if len(newBaselines) != 1 {
		t.Fatalf("expected 1 newBaseline, got %d", len(newBaselines))
	}
	if newBaselines[0].Domain != "unknown" {
		t.Errorf("domain for unregistered key should be 'unknown', got %q", newBaselines[0].Domain)
	}
}
