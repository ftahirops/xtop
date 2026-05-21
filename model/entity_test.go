package model

import (
	"encoding/json"
	"testing"
)

// TestEntityGraphBasic asserts the core ops: Add, Lookup, replace-on-same-ID.
func TestEntityGraphBasic(t *testing.T) {
	g := NewEntityGraph()
	if g.Len() != 0 {
		t.Fatalf("new graph: len=%d, want 0", g.Len())
	}

	host := Entity{ID: "host", Kind: EntityKindHost, Name: "test-host"}
	g.Add(host)

	cg := Entity{ID: "cgroup:/system.slice/mongod.service", Kind: EntityKindCgroup,
		Name: "mongod.service", OwnerID: "host"}
	g.Add(cg)

	proc := Entity{ID: "pid:1234", Kind: EntityKindProcess, Name: "mongod",
		OwnerID: "cgroup:/system.slice/mongod.service"}
	g.Add(proc)

	if g.Len() != 3 {
		t.Fatalf("len=%d, want 3", g.Len())
	}

	if e := g.Lookup("pid:1234"); e == nil || e.Name != "mongod" {
		t.Errorf("Lookup(pid:1234) = %v", e)
	}
	if e := g.Lookup("nope"); e != nil {
		t.Errorf("Lookup(nope) = %v, want nil", e)
	}

	// Replace
	updated := Entity{ID: "pid:1234", Kind: EntityKindProcess, Name: "mongod-renamed",
		OwnerID: "cgroup:/system.slice/mongod.service"}
	g.Add(updated)
	if g.Len() != 3 {
		t.Errorf("len after replace=%d, want 3", g.Len())
	}
	if e := g.Lookup("pid:1234"); e == nil || e.Name != "mongod-renamed" {
		t.Errorf("replace didn't take: %v", e)
	}
}

// TestEntityGraphOwnerChain asserts walking up the ownership tree.
func TestEntityGraphOwnerChain(t *testing.T) {
	g := NewEntityGraph()
	g.Add(Entity{ID: "host", Kind: EntityKindHost})
	g.Add(Entity{ID: "cgroup:/system.slice", Kind: EntityKindCgroup, OwnerID: "host"})
	g.Add(Entity{ID: "cgroup:/system.slice/mongod", Kind: EntityKindCgroup, OwnerID: "cgroup:/system.slice"})
	g.Add(Entity{ID: "pid:1234", Kind: EntityKindProcess, OwnerID: "cgroup:/system.slice/mongod"})

	owner := g.Owner("pid:1234")
	if owner == nil || owner.ID != "cgroup:/system.slice/mongod" {
		t.Errorf("Owner(pid:1234) = %v", owner)
	}

	chain := g.AncestorChain("pid:1234")
	if len(chain) != 3 {
		t.Fatalf("chain len=%d, want 3", len(chain))
	}
	wantIDs := []string{"cgroup:/system.slice/mongod", "cgroup:/system.slice", "host"}
	for i, e := range chain {
		if e.ID != wantIDs[i] {
			t.Errorf("chain[%d].ID=%q, want %q", i, e.ID, wantIDs[i])
		}
	}
}

// TestEntityGraphCycleGuard asserts AncestorChain doesn't loop forever
// on a cyclic graph (pathological but observed in malformed cgroup
// trees).
func TestEntityGraphCycleGuard(t *testing.T) {
	g := NewEntityGraph()
	g.Add(Entity{ID: "a", OwnerID: "b"})
	g.Add(Entity{ID: "b", OwnerID: "a"})
	chain := g.AncestorChain("a")
	if len(chain) > 64 {
		t.Errorf("cycle guard broken: chain len=%d", len(chain))
	}
	// We expect chain to be [b] then stop (b's owner is a, already visited).
	if len(chain) != 1 || chain[0].ID != "b" {
		t.Errorf("chain on cycle = %d entries, want 1 (b)", len(chain))
	}
}

// TestEntityGraphJSONRoundtrip asserts the graph serializes losslessly
// and Reindex rebuilds the lookup map.
func TestEntityGraphJSONRoundtrip(t *testing.T) {
	g := NewEntityGraph()
	g.Add(Entity{ID: "host", Kind: EntityKindHost})
	g.Add(Entity{ID: "pid:1", Kind: EntityKindProcess, OwnerID: "host",
		Tags: map[string]string{"comm": "init"}})

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored EntityGraph
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	restored.Reindex()

	if restored.Len() != 2 {
		t.Errorf("restored len=%d, want 2", restored.Len())
	}
	if e := restored.Lookup("pid:1"); e == nil || e.Tags["comm"] != "init" {
		t.Errorf("Lookup after roundtrip = %v", e)
	}
}

// TestNilSafeOps asserts Lookup/Owner/AncestorChain don't panic on nil.
func TestNilSafeOps(t *testing.T) {
	var g *EntityGraph
	if e := g.Lookup("x"); e != nil {
		t.Errorf("nil.Lookup = %v", e)
	}
	if e := g.Owner("x"); e != nil {
		t.Errorf("nil.Owner = %v", e)
	}
	if c := g.AncestorChain("x"); len(c) != 0 {
		t.Errorf("nil.AncestorChain = %v", c)
	}
	if n := g.Len(); n != 0 {
		t.Errorf("nil.Len = %d", n)
	}
}
