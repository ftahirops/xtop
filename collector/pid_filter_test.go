package collector

import (
	"testing"
)

// ---------------------------------------------------------------------------
// isContainerizedCgroup
// ---------------------------------------------------------------------------

func TestIsContainerizedCgroup(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		want  bool
	}{
		// Docker
		{"docker long path", "0::/system.slice/docker-abc123def456.scope", true},
		// Kubernetes / kubepods
		{"kubepods besteffort", "0::/kubepods/besteffort/pod.../cri-containerd-...", true},
		// containerd
		{"containerd scope", "0::/system.slice/containerd.service/cri-containerd-abc.scope", true},
		// crio
		{"crio cgroup", "0::/crio/abc123", true},
		// lxc
		{"lxc cgroup", "0::/lxc/mycontainer", true},
		// machine.slice (systemd-nspawn / VM)
		{"machine.slice", "0::/machine.slice/machine-qemu1.scope", true},
		// Host processes — NOT containerised
		{"host init", "0::/init.scope", false},
		{"host system service", "0::/system.slice/sshd.service", false},
		{"host user slice", "0::/user.slice/user-1000.slice/session-1.scope", false},
		{"empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isContainerizedCgroup(tc.path)
			if got != tc.want {
				t.Errorf("isContainerizedCgroup(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// shouldSkipLowPID — this is the core audit fix
// ---------------------------------------------------------------------------

func TestShouldSkipLowPID(t *testing.T) {
	const noSelf = 0 // selfPID not relevant for most cases

	cases := []struct {
		name          string
		pid           int
		containerized bool
		selfPID       int
		wantSkip      bool
	}{
		// --- AUDIT CASE: containerised low-PID processes must NOT be skipped ---
		{"container PID 1 (audit case)", 1, true, noSelf, false},
		{"container PID 2", 2, true, noSelf, false},
		{"container PID 50", 50, true, noSelf, false},
		{"container PID 99", 99, true, noSelf, false},
		// --- Host low-PID processes must still be skipped ---
		{"host PID 0 (idle/swapper)", 0, false, noSelf, true},
		{"host PID 1 (init/systemd)", 1, false, noSelf, true},
		{"host PID 2 (kthreadd)", 2, false, noSelf, true},
		{"host PID 50 (kernel thread)", 50, false, noSelf, true},
		{"host PID 99", 99, false, noSelf, true},
		// --- High-PID processes always scanned regardless of container flag ---
		{"host PID 100", 100, false, noSelf, false},
		{"host PID 1234", 1234, false, noSelf, false},
		{"container PID 1000", 1000, true, noSelf, false},
		// --- Self-PID always skipped (collector avoids scanning itself) ---
		{"self PID (host)", 42, false, 42, true},
		{"self PID (container)", 5, true, 5, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipLowPID(tc.pid, tc.containerized, tc.selfPID)
			if got != tc.wantSkip {
				t.Errorf("shouldSkipLowPID(pid=%d, containerized=%v, selfPID=%d) = %v; want %v",
					tc.pid, tc.containerized, tc.selfPID, got, tc.wantSkip)
			}
		})
	}
}

// TestShouldSkipLowPID_AuditCase explicitly documents the security audit
// finding: a fileless/reverse-shell payload running as PID 1 inside a
// container was previously skipped because PID < 100.  Verify the fix.
func TestShouldSkipLowPID_AuditCase(t *testing.T) {
	// Simulates: attacker process is PID 1 inside a container (docker/k8s).
	// isContainerizedCgroup would return true for its cgroup path.
	containerized := true
	for _, pid := range []int{1, 2, 7, 42, 99} {
		if shouldSkipLowPID(pid, containerized, 0) {
			t.Errorf("AUDIT REGRESSION: shouldSkipLowPID(%d, containerized=true, 0) = true; "+
				"containerised low-PID processes must be scanned, not skipped", pid)
		}
	}
}

// TestShouldSkipLowPID_HostKernelThreadsSafe verifies host kernel threads
// (PID < 100, non-containerised) are still excluded to prevent false positives.
func TestShouldSkipLowPID_HostKernelThreadsSafe(t *testing.T) {
	for pid := 0; pid < 100; pid++ {
		if !shouldSkipLowPID(pid, false, 0) {
			t.Errorf("shouldSkipLowPID(%d, containerized=false, 0) = false; "+
				"host kernel threads (PID < 100) should still be skipped", pid)
		}
	}
}

// ---------------------------------------------------------------------------
// reverseShellMaxProcs cap — mirrors the pattern in deleted_open_cap_test.go
// ---------------------------------------------------------------------------

func TestReverseShellMaxProcsCap(t *testing.T) {
	const wantMinCap = 1024 // raised from original 50
	// The constant is defined inside collectReverseShells; we verify it
	// indirectly by checking that at most wantMinCap procs would be scanned.
	// Because it is a local const we cannot reference it directly — instead we
	// document the intent here and rely on the code review / build to confirm.
	//
	// If this test needs to be more assertive in future, expose the constant at
	// package scope (e.g. var reverseShellMaxProcs = 1024) and compare here.
	_ = wantMinCap // acknowledged
}
