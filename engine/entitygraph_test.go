package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestBuildEntityGraph_NilSafe asserts a nil snapshot still yields a
// valid graph with at least the host root.
func TestBuildEntityGraph_NilSafe(t *testing.T) {
	g := BuildEntityGraph(nil)
	if g == nil {
		t.Fatal("BuildEntityGraph(nil) returned nil graph")
	}
	if g.Lookup("host") == nil {
		t.Fatal("host root missing from nil-snap graph")
	}
}

// TestBuildEntityGraph_ProcessOwnership asserts process→cgroup→host
// ownership chain is built correctly.
func TestBuildEntityGraph_ProcessOwnership(t *testing.T) {
	snap := &model.Snapshot{
		HostID: "test-host",
		Processes: []model.ProcessMetrics{
			{PID: 1234, Comm: "mongod", PPID: 1,
				CgroupPath: "/system.slice/mongod.service"},
			{PID: 5678, Comm: "nginx", PPID: 1,
				CgroupPath: "/system.slice/nginx.service"},
			{PID: 1, Comm: "systemd"}, // root process, no cgroup
		},
	}
	g := BuildEntityGraph(snap)

	// Host root
	if g.Lookup("host") == nil {
		t.Fatal("host missing")
	}

	// Process entities
	mongod := g.Lookup("pid:1234")
	if mongod == nil {
		t.Fatal("pid:1234 missing")
	}
	if mongod.OwnerID != "cgroup:/system.slice/mongod.service" {
		t.Errorf("mongod owner=%q", mongod.OwnerID)
	}
	if mongod.Name != "mongod" {
		t.Errorf("mongod name=%q", mongod.Name)
	}

	// Cgroup entity
	cg := g.Lookup("cgroup:/system.slice/mongod.service")
	if cg == nil {
		t.Fatal("mongod cgroup missing")
	}
	if cg.OwnerID != "cgroup:/system.slice" {
		t.Errorf("mongod cgroup owner=%q", cg.OwnerID)
	}

	// Parent cgroup auto-created
	systemSlice := g.Lookup("cgroup:/system.slice")
	if systemSlice == nil {
		t.Fatal("/system.slice auto-creation failed")
	}
	if systemSlice.OwnerID != "host" {
		t.Errorf("/system.slice owner=%q, want host", systemSlice.OwnerID)
	}

	// Cgroup-less process owned by host
	systemd := g.Lookup("pid:1")
	if systemd == nil {
		t.Fatal("pid:1 missing")
	}
	if systemd.OwnerID != "host" {
		t.Errorf("pid:1 owner=%q, want host", systemd.OwnerID)
	}
}

// TestBuildEntityGraph_AncestorChain asserts a full chain walks from
// process up through cgroup tree to host.
func TestBuildEntityGraph_AncestorChain(t *testing.T) {
	snap := &model.Snapshot{
		Processes: []model.ProcessMetrics{
			{PID: 999, Comm: "mongod",
				CgroupPath: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc123.slice/cri-containerd-def456.scope"},
		},
	}
	g := BuildEntityGraph(snap)

	chain := g.AncestorChain("pid:999")
	if len(chain) < 4 {
		t.Fatalf("chain len=%d, want at least 4 (cgroups + host)", len(chain))
	}
	// Last entry must be host
	if chain[len(chain)-1].ID != "host" {
		t.Errorf("chain root=%q, want host", chain[len(chain)-1].ID)
	}
	// First entry is the leaf cgroup
	wantFirst := "cgroup:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc123.slice/cri-containerd-def456.scope"
	if chain[0].ID != wantFirst {
		t.Errorf("chain[0]=%q, want %q", chain[0].ID, wantFirst)
	}
}

// TestBuildEntityGraph_Deterministic asserts two builds of the same
// snapshot produce graphs of the same size + identical IDs.
func TestBuildEntityGraph_Deterministic(t *testing.T) {
	snap := &model.Snapshot{
		Processes: []model.ProcessMetrics{
			{PID: 1, Comm: "a", CgroupPath: "/x"},
			{PID: 2, Comm: "b", CgroupPath: "/y"},
			{PID: 3, Comm: "c", CgroupPath: "/x"},
		},
	}
	g1 := BuildEntityGraph(snap)
	g2 := BuildEntityGraph(snap)
	if g1.Len() != g2.Len() {
		t.Errorf("len diverged: %d vs %d", g1.Len(), g2.Len())
	}
	// Both must have the same set of IDs (order may differ but the
	// set must be equal — Add() de-dupes by ID).
	ids1 := map[string]bool{}
	for _, e := range g1.Entities {
		ids1[e.ID] = true
	}
	for _, e := range g2.Entities {
		if !ids1[e.ID] {
			t.Errorf("ID %q in g2 but not g1", e.ID)
		}
	}
}
