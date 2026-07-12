//go:build linux

package engine

import "testing"

// TestStealBeatsOversubscription: when CPU steal is genuinely present, the
// hypervisor-steal narrative is the root cause even though run-queue and PSI
// also fire (stolen time makes tasks pile up). The steal pattern must win over
// the generic CPU Oversubscription pattern.
func TestStealBeatsOversubscription(t *testing.T) {
	pat := MatchPattern(firedResult("cpu.steal", "cpu.psi", "cpu.runqueue"))
	if pat == nil {
		t.Fatal("expected a pattern match")
	}
	if pat.Name == "CPU Oversubscription" {
		t.Fatalf("steal scenario masked by oversubscription: %q", pat.Narrative)
	}
	if pat.Name != "VM Noisy Neighbor" {
		t.Fatalf("expected VM Noisy Neighbor to win with real steal, got %q", pat.Name)
	}
}

// TestOversubscriptionWithoutSteal: with no steal, run-queue + PSI is honest
// oversubscription.
func TestOversubscriptionWithoutSteal(t *testing.T) {
	pat := MatchPattern(firedResult("cpu.psi", "cpu.runqueue"))
	if pat == nil || pat.Name != "CPU Oversubscription" {
		got := "nil"
		if pat != nil {
			got = pat.Name
		}
		t.Fatalf("expected CPU Oversubscription without steal, got %s", got)
	}
}

// TestConntrackExhaustionNeedsConntrackDrops reproduces the wrong-drop-source
// bug: generic NIC/qdisc packet drops (net.drops) plus a busy conntrack table
// must NOT be labeled "conntrack exhaustion" — that needs conntrack-specific
// drops (net.conntrack.drops).
func TestConntrackExhaustionNeedsConntrackDrops(t *testing.T) {
	pat := MatchPattern(firedResult("net.conntrack", "net.drops"))
	if pat != nil && pat.Name == "Conntrack Exhaustion" {
		t.Fatalf("generic drops misattributed to conntrack exhaustion: %q", pat.Narrative)
	}
}
