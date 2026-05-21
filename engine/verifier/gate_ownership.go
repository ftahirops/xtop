package verifier

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

// ownershipConsistencyGate asserts the candidate's claimed root entity
// is actually present in the entity graph AND is a Kind that can own
// the relevant resource. Per NEXTGEN §5: "does the claimed root entity
// actually own the stressed resource?"
//
// Failure modes this catches:
//   - candidate names a PID that's already dead (gone from the graph)
//   - candidate names "the entire host" when the bottleneck is clearly
//     attributable to a specific cgroup
//   - candidate names a cgroup that doesn't exist (malformed input)
//   - candidate has an empty RootEntityID but supporting facts point
//     to a non-host entity (inconsistent attribution)
//
// Passes when:
//   - RootEntityID is empty AND all supporting facts are host-scope
//     (a defensible "the host as a whole" candidate)
//   - RootEntityID resolves in the graph AND its Kind is appropriate
//     for the domain (process/cgroup/service for cpu/mem/io,
//     anything for network)
type ownershipConsistencyGate struct{}

func (ownershipConsistencyGate) ID() string { return "ownership_consistency" }

func (ownershipConsistencyGate) Evaluate(c Candidate, facts []model.Fact, graph *model.EntityGraph) model.GateResult {
	if graph == nil {
		return model.GateResult{
			GateID: "ownership_consistency",
			Passed: false,
			Reason: "no entity graph available — verifier ran on a pre-Phase-3 result",
		}
	}

	// Index facts by ID so we can resolve SupportingFactIDs back to
	// the actual Fact.EntityID fields.
	byID := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		byID[f.ID] = f
	}
	supportingEntities := map[string]bool{}
	for _, fid := range c.SupportingFactIDs {
		if f, ok := byID[fid]; ok {
			supportingEntities[f.EntityID] = true
		}
	}

	// Case 1: empty root entity = "host-scope" candidate. Valid IFF
	// every supporting fact is also host-scope (or has no EntityID).
	if c.RootEntityID == "" {
		for ent := range supportingEntities {
			if ent != "" && ent != "host" {
				return model.GateResult{
					GateID:    "ownership_consistency",
					Passed:    false,
					Reason:    fmt.Sprintf("candidate is host-scope but supporting fact references entity %q", ent),
					FactsUsed: c.SupportingFactIDs,
				}
			}
		}
		return model.GateResult{
			GateID:    "ownership_consistency",
			Passed:    true,
			Reason:    "host-scope candidate with consistent host-scope evidence",
			FactsUsed: c.SupportingFactIDs,
		}
	}

	// Case 2: non-empty root entity must resolve in the graph.
	root := graph.Lookup(c.RootEntityID)
	if root == nil {
		return model.GateResult{
			GateID:    "ownership_consistency",
			Passed:    false,
			Reason:    fmt.Sprintf("root entity %q not found in entity graph (may have exited)", c.RootEntityID),
			FactsUsed: c.SupportingFactIDs,
		}
	}

	// Case 3: kind must be appropriate for the domain.
	if !kindCanOwn(root.Kind, c.Domain) {
		return model.GateResult{
			GateID:    "ownership_consistency",
			Passed:    false,
			Reason:    fmt.Sprintf("root entity kind %q cannot own resources in domain %q", root.Kind, c.Domain),
			FactsUsed: c.SupportingFactIDs,
		}
	}

	// Case 4: every supporting fact's EntityID must be in the root's
	// ownership chain (including the root itself). Equivalently: the
	// root must be an ancestor of every fact's entity.
	rootSet := map[string]bool{root.ID: true}
	for _, anc := range graph.AncestorChain(root.ID) {
		rootSet[anc.ID] = true
	}
	// Reverse direction: for each fact's entity, walk UP and see if we
	// hit the root. If yes, consistent. If no, mismatch.
	for ent := range supportingEntities {
		if ent == "" || ent == "host" {
			// host-scope facts are always consistent with any root
			// (they describe the environment the root runs in)
			continue
		}
		if rootSet[ent] {
			continue
		}
		// Walk ent's ancestors looking for the root.
		found := false
		// First check direct
		if e := graph.Lookup(ent); e != nil && e.ID == root.ID {
			continue
		}
		for _, anc := range graph.AncestorChain(ent) {
			if anc.ID == root.ID {
				found = true
				break
			}
		}
		if !found {
			return model.GateResult{
				GateID: "ownership_consistency",
				Passed: false,
				Reason: fmt.Sprintf("fact entity %q is not in the ownership chain of claimed root %q",
					ent, c.RootEntityID),
				FactsUsed: c.SupportingFactIDs,
			}
		}
	}

	return model.GateResult{
		GateID:    "ownership_consistency",
		Passed:    true,
		Reason:    fmt.Sprintf("root %q (%s) is a valid owner for %d supporting facts", c.RootEntityID, root.Kind, len(c.SupportingFactIDs)),
		FactsUsed: c.SupportingFactIDs,
	}
}

// kindCanOwn returns true if an entity of the given kind can plausibly
// own the stressed resource in the given domain.
//
// CPU / Memory / IO are owned by processes, cgroups, containers,
// services, or the host. Network is owned by anything that has a
// socket binding — for now we accept everything; a future
// ownership-aware network gate refines this.
func kindCanOwn(k model.EntityKind, d model.Domain) bool {
	switch k {
	case model.EntityKindHost,
		model.EntityKindCgroup,
		model.EntityKindContainer,
		model.EntityKindPod,
		model.EntityKindService,
		model.EntityKindRuntime,
		model.EntityKindProcess:
		return true
	case model.EntityKindMount:
		// Mounts own IO (and arguably CPU/Memory via the kernel page
		// cache). For now allow only IO.
		return d == model.DomainIO
	case model.EntityKindSocket:
		return d == model.DomainNetwork
	case model.EntityKindDependency:
		// Remote dependencies can be the cause of network/IO issues.
		return d == model.DomainNetwork || d == model.DomainIO
	}
	return false
}
