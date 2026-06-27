package engine

// configdrift_wire_test.go — P4.5 tests for kernel-param drift wiring.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestConfigDriftWire_TickTriggersDetection verifies that when the
// paramDriftDetector has a baseline and the stub snapshot returns a drifted
// value, Tick() (every 30th call) appends a config_drift_* SystemChange to
// result.Changes.
func TestConfigDriftWire_TickTriggersDetection(t *testing.T) {
	t.Parallel()

	eng := NewEngine(10, 1)
	defer eng.Close()

	// Seed the detector with a known baseline for vm.swappiness = "60".
	eng.paramDriftDetector = NewParamDriftDetector([]ConfigBaselineRecord{
		{Key: "vm.swappiness", Value: "60", Domain: "memory", FirstSeen: time.Now()},
	})

	// Stub snapshot fn returns a drifted value ("10" != "60").
	snapshotCalled := 0
	eng.configSnapshotFn = func() (map[string]string, error) {
		snapshotCalled++
		return map[string]string{"vm.swappiness": "10"}, nil
	}
	eng.configDriftEnabled = true

	// Force tickCount so that the next Tick() triggers the 30-tick check.
	eng.tickCount = 29

	// Run one Tick. We need at least two ticks for rates to be computed.
	eng.Tick()
	// First tick: tickCount becomes 30, 30%30 == 0 → should trigger.
	// But we need prev != nil for result to be non-nil. Run a 2nd tick.
	eng.tickCount = 29 // reset so next tick is 30
	_, _, result := eng.Tick()

	if snapshotCalled == 0 {
		t.Error("expected configSnapshotFn to be called, but it was not")
	}

	if result == nil {
		t.Fatal("expected non-nil result from second Tick")
	}

	found := false
	for _, ch := range result.Changes {
		if strings.HasPrefix(ch.Type, "config_drift_") && strings.Contains(ch.Detail, "vm.swappiness") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected config_drift_* SystemChange for vm.swappiness in result.Changes, got: %v", result.Changes)
	}
}

// TestConfigDriftWire_FlagOff verifies that when configDriftEnabled=false,
// no config_drift_* change is emitted and the snapshot fn is never called.
func TestConfigDriftWire_FlagOff(t *testing.T) {
	t.Parallel()

	eng := NewEngine(10, 1)
	defer eng.Close()

	eng.paramDriftDetector = NewParamDriftDetector([]ConfigBaselineRecord{
		{Key: "vm.swappiness", Value: "60", Domain: "memory", FirstSeen: time.Now()},
	})

	snapshotCalled := 0
	eng.configSnapshotFn = func() (map[string]string, error) {
		snapshotCalled++
		return map[string]string{"vm.swappiness": "10"}, nil
	}
	eng.configDriftEnabled = false // flag off

	eng.tickCount = 29
	eng.Tick()
	eng.tickCount = 29
	_, _, result := eng.Tick()

	if snapshotCalled != 0 {
		t.Errorf("expected configSnapshotFn not to be called when flag=off, but got %d calls", snapshotCalled)
	}

	if result != nil {
		for _, ch := range result.Changes {
			if strings.HasPrefix(ch.Type, "config_drift_") {
				t.Errorf("unexpected config_drift_* change when flag=off: %+v", ch)
			}
		}
	}
}

// TestSuggestedRemediation verifies that suggestedRemediation returns a
// plausible, non-empty string containing "sysctl" and the key name for
// known keys, and a generic suggestion for unknown keys.
func TestSuggestedRemediation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key        string
		oldVal     string
		wantSysctl bool
		wantKey    bool
	}{
		{"vm.swappiness", "60", true, true},
		{"net.core.somaxconn", "128", true, true},
		{"kernel.pid_max", "32768", true, true},
		{"vm.overcommit_memory", "0", true, true},
		{"unknown.param", "42", false, true},
	}

	for _, tc := range cases {
		got := suggestedRemediation(tc.key, tc.oldVal)
		if got == "" {
			t.Errorf("suggestedRemediation(%q, %q) returned empty string", tc.key, tc.oldVal)
			continue
		}
		if tc.wantSysctl && !strings.Contains(got, "sysctl") {
			t.Errorf("suggestedRemediation(%q, %q) = %q — expected to contain 'sysctl'", tc.key, tc.oldVal, got)
		}
		if tc.wantKey && !strings.Contains(got, tc.key) {
			t.Errorf("suggestedRemediation(%q, %q) = %q — expected to contain key name", tc.key, tc.oldVal, got)
		}
	}
}

// TestSuggestedRemediationNoWrite is a design-assertion test: the
// configdrift packages (collector/configdrift and engine/configdrift*.go)
// must not contain any os.WriteFile or os.OpenFile calls with write flags.
// This enforces the DETECT+EXPLAIN-only contract.
func TestSuggestedRemediationNoWrite(t *testing.T) {
	t.Parallel()

	dirs := []string{
		"../collector/configdrift",
	}
	// engine/configdrift*.go files
	engineFiles, err := filepath.Glob("configdrift*.go")
	if err != nil {
		t.Fatalf("glob configdrift*.go: %v", err)
	}
	engineRemediationFile := "configdrift_remediation.go"
	engineFiles = append(engineFiles, engineRemediationFile)

	forbiddenPatterns := []string{
		"os.WriteFile",
		"os.OpenFile",
		"ioutil.WriteFile",
	}

	checkFile := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			// File may not exist on some platforms (stubs); skip.
			return
		}
		content := string(data)
		for _, pat := range forbiddenPatterns {
			if strings.Contains(content, pat) {
				t.Errorf("NO-WRITE violation: %s contains %q — configdrift code must never write to /proc/sys or /sys", path, pat)
			}
		}
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Logf("skip dir %s: %v", dir, err)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
				checkFile(filepath.Join(dir, e.Name()))
			}
		}
	}

	for _, f := range engineFiles {
		// Skip this test file itself — it legitimately references os.WriteFile
		// in the forbidden-pattern strings being searched for.
		if f == "configdrift_wire_test.go" {
			continue
		}
		checkFile(f)
	}
}
