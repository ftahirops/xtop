package engine

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// domainFromBottleneck maps a legacy bottleneck-name string to the
// model.Domain it belongs to. Used by the Phase 4 verifier wiring to
// build Candidates from RCAEntries.
func domainFromBottleneck(b string) model.Domain {
	switch b {
	case BottleneckCPU:
		return model.DomainCPU
	case BottleneckMemory:
		return model.DomainMemory
	case BottleneckIO:
		return model.DomainIO
	case BottleneckNetwork:
		return model.DomainNetwork
	}
	return ""
}

// domainNameFromBottleneck returns a human-readable domain label.
func domainNameFromBottleneck(b string) string {
	return string(domainFromBottleneck(b))
}

// isVerifiedTier reports whether a verification tier counts as "verified" for
// labeling purposes: Tier A (confirmed) and B (verified) are trusted; Tier C
// (probable) and D (inconclusive/abstain) are not, and should be labeled.
func isVerifiedTier(t model.VerificationTier) bool {
	return t == model.TierAConfirmed || t == model.TierBVerified
}

// factIDsForDomain returns the IDs of every Fact in the given domain.
// O(len(facts)) per call — fine at ~30 facts/tick.
func factIDsForDomain(facts []model.Fact, d model.Domain) []string {
	var ids []string
	for _, f := range facts {
		if f.Domain == d {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

// BuildEntityGraph constructs the host-local entity graph for one tick.
// NEXTGEN Phase 3 step 1 of the rollout: only process + cgroup nodes
// for now, with ownership edges. Future commits add service nodes,
// socket nodes, mount/container/pod nodes.
//
// Ownership rules:
//   - every process is owned by its cgroup (or by "host" if cgroup is
//     empty or "/" — the kernel root)
//   - every cgroup is owned by its parent cgroup, recursively up to
//     "host" (which owns the root cgroup)
//
// Cost: O(P + C) where P=processes, C=cgroups. On a 500-proc host the
// graph builds in ~100µs — within the engine's per-tick budget.
//
// The graph is read-only after construction. Callers MUST NOT mutate
// Entities or the byID map after this returns.
func BuildEntityGraph(snap *model.Snapshot) *model.EntityGraph {
	g := model.NewEntityGraph()
	if snap == nil {
		// Always include the host node so consumers can rely on its
		// existence even on degenerate input.
		g.Add(model.Entity{ID: "host", Kind: model.EntityKindHost})
		return g
	}

	hostName := snap.HostID
	if hostName == "" {
		hostName = "host"
	}
	g.Add(model.Entity{
		ID:   "host",
		Kind: model.EntityKindHost,
		Name: hostName,
	})

	// Pass 1: emit cgroup entities. Build them depth-first by walking
	// each unique cgroup path and recording every intermediate
	// directory as its own entity. This is what gives us a clean
	// ancestor chain at lookup time.
	cgroupPaths := collectCgroupPaths(snap)
	for _, path := range cgroupPaths {
		addCgroupChain(g, path)
	}

	// Pass 2: emit process entities, each owned by its cgroup (or
	// "host" if it has no cgroup attribution).
	for _, proc := range snap.Processes {
		id := fmt.Sprintf("pid:%d", proc.PID)
		ownerID := "host"
		if proc.CgroupPath != "" && proc.CgroupPath != "/" {
			ownerID = "cgroup:" + proc.CgroupPath
			// Defensive: if we somehow didn't pre-create this cgroup
			// in pass 1, do it now so the OwnerID resolves.
			if g.Lookup(ownerID) == nil {
				addCgroupChain(g, proc.CgroupPath)
			}
		}
		tags := map[string]string{
			"pid":  strconv.Itoa(proc.PID),
			"comm": proc.Comm,
		}
		if proc.PPID > 0 {
			tags["ppid"] = strconv.Itoa(proc.PPID)
		}
		g.Add(model.Entity{
			ID:      id,
			Kind:    model.EntityKindProcess,
			Name:    proc.Comm,
			OwnerID: ownerID,
			Tags:    tags,
		})
	}
	return g
}

// collectCgroupPaths returns the deduplicated set of cgroup paths seen
// in the snapshot — both from explicit Cgroups entries and from each
// process's CgroupPath. Ordered for deterministic graph construction.
func collectCgroupPaths(snap *model.Snapshot) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || p == "/" {
			return
		}
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, cg := range snap.Cgroups {
		add(cg.Path)
	}
	for _, proc := range snap.Processes {
		add(proc.CgroupPath)
	}
	return out
}

// addCgroupChain inserts the given cgroup path AND all its ancestors
// into the graph. Each level is owned by its parent; the topmost level
// is owned by "host".
//
// Example: "/system.slice/mongod.service" produces:
//
//	cgroup:/system.slice/mongod.service  owner=cgroup:/system.slice
//	cgroup:/system.slice                 owner=host
//
// Idempotent: re-adding an existing cgroup path is a no-op (EntityGraph.Add
// replaces by ID).
func addCgroupChain(g *model.EntityGraph, path string) {
	path = filepath.Clean(path)
	if path == "" || path == "/" || path == "." {
		return
	}
	// Walk from leaf to root, recording each level.
	cur := path
	for {
		parent := filepath.Dir(cur)
		ownerID := "host"
		if parent != "" && parent != "/" && parent != "." {
			ownerID = "cgroup:" + parent
		}
		g.Add(model.Entity{
			ID:      "cgroup:" + cur,
			Kind:    model.EntityKindCgroup,
			Name:    filepath.Base(cur),
			OwnerID: ownerID,
			Tags:    map[string]string{"path": cur},
		})
		if ownerID == "host" {
			return
		}
		// Move up one level. Stop at root.
		cur = strings.TrimPrefix(ownerID, "cgroup:")
		if cur == "" || cur == "/" {
			return
		}
	}
}
