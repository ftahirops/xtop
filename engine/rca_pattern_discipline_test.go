//go:build linux

package engine

import "testing"

// A specific-cause pattern must NOT fire when only its generic co-signals are
// present — the defining evidence has to be there. Each negative case fires
// everything EXCEPT the defining evidence and asserts the named pattern does not win.
func TestPatternsRequireDefiningEvidence(t *testing.T) {
	negatives := []struct {
		name       string // pattern that must NOT match
		firedNoDef []string
	}{
		// SEED-A: hypervisor-steal narrative must need actual steal, not just CPU PSI.
		{"VM Noisy Neighbor", []string{"cpu.psi"}},
		// VM CPU throttle must need real throttling, not just guest CPU PSI.
		{"VM CPU Throttle", []string{"pve.vm.cpupsi"}},
		// VM memory pressure must need the mem-limit signal, not just PSI+swap.
		{"VM Memory Pressure", []string{"pve.vm.mempsi", "pve.vm.swap"}},
		// "D-state threads accumulating" must need io.dstate, not just util+latency.
		{"Disk IO Saturation", []string{"io.disk.util", "io.disk.latency"}},
		// "retransmits with packet drops" must need retransmits, not just drops+softirq.
		{"Network Congestion", []string{"net.drops", "net.softirq"}},
	}
	for _, tc := range negatives {
		pat := MatchPattern(firedResult(tc.firedNoDef...))
		if pat != nil && pat.Name == tc.name {
			t.Errorf("%q fired without its defining evidence (fired=%v -> %q)",
				tc.name, tc.firedNoDef, pat.Narrative)
		}
	}
}

// Positive guards: with the defining evidence present, the pattern SHOULD fire.
func TestPatternsFireWithDefiningEvidence(t *testing.T) {
	positives := []struct {
		name  string
		fired []string
	}{
		{"VM Noisy Neighbor", []string{"cpu.steal", "cpu.psi"}},
		{"VM CPU Throttle", []string{"pve.vm.throttle", "pve.vm.cpupsi"}},
		{"VM Memory Pressure", []string{"pve.vm.memlimit", "pve.vm.mempsi", "pve.vm.swap"}},
		{"Disk IO Saturation", []string{"io.disk.util", "io.dstate", "io.disk.latency"}},
		{"Network Congestion", []string{"net.tcp.retrans", "net.drops", "net.softirq"}},
	}
	for _, tc := range positives {
		pat := MatchPattern(firedResult(tc.fired...))
		if pat == nil || pat.Name != tc.name {
			got := "nil"
			if pat != nil {
				got = pat.Name
			}
			t.Errorf("%q should fire with %v, got %s", tc.name, tc.fired, got)
		}
	}
}
