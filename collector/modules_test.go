package collector

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempConfig redirects ModuleConfigPath at the location the test owns,
// then runs fn. Tests can't share the real ~/.xtop/modules.json without
// stomping each other.
func withTempConfig(t *testing.T, fn func()) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "modules.json")
	t.Setenv("XTOP_MODULES_PATH", tmp)
	fn()
}

func TestResolve_DefaultProfileIsStandard(t *testing.T) {
	withTempConfig(t, func() {
		c := LoadModuleConfig()
		if c.Profile != "standard" {
			t.Errorf("default profile = %q, want standard", c.Profile)
		}
		enabled := ResolveEnabledModules(c)
		// Essentials always on
		for _, m := range moduleCatalog {
			if m.Tier == TierEssential && !enabled[m.Name] {
				t.Errorf("essential module %q must be enabled", m.Name)
			}
		}
		// Heavy never on in standard
		if enabled["deep-scan"] || enabled["fileless"] || enabled["profiler"] {
			t.Error("standard profile should not enable Heavy modules")
		}
		// Standard tier ON
		if !enabled["cgroup"] || !enabled["apps"] || !enabled["runtime"] {
			t.Error("standard profile should enable cgroup, apps, runtime")
		}
	})
}

func TestResolve_MinimalLeavesOnlyEssentials(t *testing.T) {
	withTempConfig(t, func() {
		c := ModuleConfig{Profile: "minimal"}
		enabled := ResolveEnabledModules(c)
		for n, on := range enabled {
			tier, _ := tierOf(n)
			if on && tier != TierEssential {
				t.Errorf("minimal profile enabled non-essential %q", n)
			}
			if !on && tier == TierEssential {
				t.Errorf("minimal profile disabled essential %q", n)
			}
		}
	})
}

func TestResolve_InvestigationEnablesEverything(t *testing.T) {
	withTempConfig(t, func() {
		c := ModuleConfig{Profile: "investigation"}
		enabled := ResolveEnabledModules(c)
		for _, m := range moduleCatalog {
			if !enabled[m.Name] {
				t.Errorf("investigation should enable %s/%s, got off", m.Tier, m.Name)
			}
		}
	})
}

func TestResolve_UserDisableOverridesProfile(t *testing.T) {
	withTempConfig(t, func() {
		c := ModuleConfig{
			Profile:  "investigation",
			Disabled: []string{"profiler", "fileless"},
		}
		enabled := ResolveEnabledModules(c)
		if enabled["profiler"] || enabled["fileless"] {
			t.Errorf("user disable list should override profile: profiler=%v fileless=%v",
				enabled["profiler"], enabled["fileless"])
		}
		// Sibling Heavy modules still on
		if !enabled["bigfiles"] {
			t.Error("disabling profiler/fileless should not affect bigfiles")
		}
	})
}

func TestResolve_CannotDisableEssential(t *testing.T) {
	withTempConfig(t, func() {
		c := ModuleConfig{
			Profile:  "minimal",
			Disabled: []string{"cpu", "memory", "psi"},
		}
		enabled := ResolveEnabledModules(c)
		for _, n := range []string{"cpu", "memory", "psi"} {
			if !enabled[n] {
				t.Errorf("user attempted to disable Essential %q — must remain enabled", n)
			}
		}
	})
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	withTempConfig(t, func() {
		want := ModuleConfig{
			Profile:  "sre",
			Disabled: []string{"smart"},
		}
		if err := SaveModuleConfig(want); err != nil {
			t.Fatalf("save: %v", err)
		}
		got := LoadModuleConfig()
		if got.Profile != want.Profile {
			t.Errorf("profile: %q vs %q", got.Profile, want.Profile)
		}
		if len(got.Disabled) != 1 || got.Disabled[0] != "smart" {
			t.Errorf("disabled list lost: %v", got.Disabled)
		}
		if got.UpdatedAt.IsZero() {
			t.Error("UpdatedAt should be stamped on save")
		}
	})
}

func TestSetProfile_RejectsUnknown(t *testing.T) {
	withTempConfig(t, func() {
		_, err := SetProfile("nonsense")
		if err == nil {
			t.Error("expected error for unknown profile")
		}
	})
}

func TestToggleModule_RefusesEssential(t *testing.T) {
	withTempConfig(t, func() {
		_, err := ToggleModule("cpu")
		if err == nil {
			t.Error("toggle of Essential 'cpu' should error")
		}
	})
}

func TestToggleModule_AddsAndRemovesFromDisabled(t *testing.T) {
	withTempConfig(t, func() {
		// First call: turn off (add to Disabled).
		on, err := ToggleModule("smart")
		if err != nil || on {
			t.Fatalf("first toggle: on=%v err=%v; want on=false", on, err)
		}
		c := LoadModuleConfig()
		if len(c.Disabled) != 1 || c.Disabled[0] != "smart" {
			t.Errorf("expected ['smart'] in Disabled, got %v", c.Disabled)
		}
		// Second call: turn on (remove).
		on, err = ToggleModule("smart")
		if err != nil || !on {
			t.Fatalf("second toggle: on=%v err=%v; want on=true", on, err)
		}
		c = LoadModuleConfig()
		for _, d := range c.Disabled {
			if d == "smart" {
				t.Error("smart should no longer be in Disabled list")
			}
		}
	})
}

func TestFilterByConfig_StableOrder(t *testing.T) {
	withTempConfig(t, func() {
		c := ModuleConfig{Profile: "sre"}
		out1 := FilterByConfig(c)
		out2 := FilterByConfig(c)
		if len(out1) != len(out2) {
			t.Fatalf("FilterByConfig non-deterministic length: %d vs %d", len(out1), len(out2))
		}
		for i := range out1 {
			if out1[i] != out2[i] {
				t.Errorf("FilterByConfig non-deterministic order at %d: %q vs %q",
					i, out1[i], out2[i])
			}
		}
	})
}

func TestModuleConfigPath_RespectsEnv(t *testing.T) {
	t.Setenv("XTOP_MODULES_PATH", "/tmp/xtop-modules-test.json")
	got := ModuleConfigPath()
	if got != "/tmp/xtop-modules-test.json" {
		t.Errorf("env override ignored: %q", got)
	}
	_ = os.Remove(got)
}
