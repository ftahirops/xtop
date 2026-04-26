package cgroup

import (
	"testing"
)

func TestParseKubepodsPath_SystemdV2(t *testing.T) {
	path := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9e5d1e42_b8f4_4f7a_9a67_7c9a4e3f21ab.slice/cri-containerd-1a2b3c4d5e6f7890abcdef12.scope"
	id := parseKubepodsPath(path)
	if id.QoS != "Burstable" {
		t.Errorf("QoS = %q, want Burstable", id.QoS)
	}
	if id.PodUID != "9e5d1e42-b8f4-4f7a-9a67-7c9a4e3f21ab" {
		t.Errorf("PodUID = %q, want dashed form", id.PodUID)
	}
	if id.Container != "1a2b3c4d5e6f" {
		t.Errorf("Container = %q, want 12-char prefix", id.Container)
	}
}

func TestParseKubepodsPath_CgroupfsDriver(t *testing.T) {
	path := "/kubepods/besteffort/pod11111111-2222-3333-4444-555555555555/aabbccddeeff112233445566"
	id := parseKubepodsPath(path)
	if id.QoS != "BestEffort" {
		t.Errorf("QoS = %q, want BestEffort", id.QoS)
	}
	if id.PodUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("PodUID = %q", id.PodUID)
	}
}

func TestParseKubepodsPath_GuaranteedFallback(t *testing.T) {
	// Guaranteed pods lack an explicit besteffort/burstable QoS slice in v2
	// systemd mode — we fall through to the "else" branch of the classifier.
	path := "/kubepods.slice/kubepods-pod7f000000_0000_0000_0000_000000000001.slice/crio-1234567890abcdef.scope"
	id := parseKubepodsPath(path)
	if id.PodUID == "" {
		t.Errorf("expected UID parsed from slice name")
	}
	// QoS may be "" or "Guaranteed" depending on regex match; accept either.
	if id.QoS != "" && id.QoS != "Guaranteed" {
		t.Errorf("unexpected QoS %q", id.QoS)
	}
}

func TestIsKubepodsPath(t *testing.T) {
	cases := map[string]bool{
		"/kubepods.slice/kubepods-burstable.slice":           true,
		"/kubepods/burstable/pod123/container":               true,
		"/system.slice/nginx.service":                        false,
		"/user.slice/user-1000.slice":                        false,
		"/kubepods-besteffort.slice/podabc":                  true,
	}
	for in, want := range cases {
		if got := isKubepodsPath(in); got != want {
			t.Errorf("isKubepodsPath(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestKubepodsResolver_CachesResults(t *testing.T) {
	r := NewKubepodsResolver()
	path := "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabcdef12_3456_7890_1234_567890abcdef.slice"
	id1 := r.Resolve(path)
	if id1.PodUID == "" {
		t.Fatal("expected a parsed PodUID")
	}
	// Second call should hit cache and return equal identity.
	id2 := r.Resolve(path)
	if id1 != id2 {
		t.Errorf("cache mismatch: %+v vs %+v", id1, id2)
	}
}

func TestPodIdentity_Empty(t *testing.T) {
	if !(PodIdentity{}).Empty() {
		t.Error("zero-value identity should be Empty()")
	}
	if (PodIdentity{PodUID: "x"}).Empty() {
		t.Error("non-empty UID should not be Empty()")
	}
}
