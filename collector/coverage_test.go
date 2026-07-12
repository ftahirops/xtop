//go:build linux

package collector

import "testing"

// TestOmittedSignals covers readiness-review Finding #6: lean/fleet mode omits
// several collectors, and consumers need to know which signal classes were not
// observable. OmittedSignals reports the rich-minus-lean collector set.
func TestOmittedSignals(t *testing.T) {
	if got := OmittedSignals(ModeRich); len(got) != 0 {
		t.Fatalf("rich mode omits nothing, got %v", got)
	}

	lean := OmittedSignals(ModeLean)
	if len(lean) == 0 {
		t.Fatal("lean mode should report omitted signal classes")
	}
	// bigfiles is one of the collectors excluded from lean mode.
	found := false
	for _, s := range lean {
		if s == "bigfiles" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'bigfiles' among omitted lean signals, got %v", lean)
	}
}
