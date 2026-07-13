//go:build linux

package apps

import "testing"

// TestRuntimeFromCgroup verifies container-runtime classification from a PID's
// cgroup contents — so the apps table can show "docker" vs "native".
func TestRuntimeFromCgroup(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"docker scope", "0::/system.slice/docker-abc123.scope\n", "docker"},
		{"docker legacy", "12:pids:/docker/abc123\n", "docker"},
		{"docker DAEMON is native", "0::/system.slice/docker.service\n", "native"},
		{"k8s pod", "0::/kubepods/besteffort/pod-x/abc\n", "k8s"},
		{"k8s beats containerd", "0::/kubepods/pod-x/cri-containerd-abc.scope\n", "k8s"},
		{"standalone containerd", "0::/system.slice/containerd-abc.scope\n", "containerd"},
		{"containerd DAEMON is native", "0::/system.slice/containerd.service\n", "native"},
		{"podman libpod", "0::/machine.slice/libpod-abc.scope\n", "podman"},
		{"native service", "0::/system.slice/postgresql.service\n", "native"},
		{"empty", "", "native"},
	}
	for _, tc := range cases {
		if got := runtimeFromCgroup(tc.in); got != tc.want {
			t.Errorf("%s: runtimeFromCgroup(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
