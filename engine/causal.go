package engine

import (
	"strings"

	"github.com/ftahirops/xtop/model"
)

// causalRule defines a cause→effect relationship between evidence IDs.
type causalRule struct {
	from, to, rule string
	weight         float64
}

var causalRules = []causalRule{
	// IO domain
	{"io.disk.latency", "io.dstate", "latency→dstate", 0.9},
	{"io.psi", "io.dstate", "psi→dstate", 0.8},
	{"io.fsfull", "io.writeback", "fsfull→writeback", 0.6},
	{"io.disk.util", "io.disk.latency", "util→latency", 0.7},
	{"io.writeback", "io.disk.latency", "writeback→latency", 0.5},

	// Memory domain
	{"mem.available.low", "mem.reclaim.direct", "lowmem→reclaim", 0.9},
	{"mem.available.low", "mem.major.faults", "lowmem→faults", 0.7},
	{"mem.available.low", "mem.swap.activity", "lowmem→swap", 0.85},
	{"mem.oom.kills", "mem.available.low", "oom→lowmem", 0.95},

	// Cross-domain: memory → IO
	{"mem.swap.activity", "io.psi", "swap→iopsi", 0.7},
	{"mem.swap.activity", "io.disk.latency", "swap→iolatency", 0.65},
	{"mem.reclaim.direct", "io.disk.latency", "reclaim→iolatency", 0.6},
	{"mem.major.faults", "io.disk.latency", "faults→iolatency", 0.5},

	// CPU domain
	{"cpu.runqueue", "cpu.psi", "runqueue→psi", 0.85},
	{"cpu.cgroup.throttle", "cpu.runqueue", "throttle→runqueue", 0.8},
	{"cpu.steal", "cpu.psi", "steal→psi", 0.9},
	{"cpu.ctxswitch", "cpu.psi", "ctxswitch→psi", 0.5},
	{"cpu.ctxswitch", "cpu.runqueue", "ctxswitch→runqueue", 0.4},

	// Cross-domain: CPU → IO
	{"cpu.psi", "io.dstate", "cpupsi→dstate", 0.4},

	// Network domain
	{"net.tcp.retrans", "net.softirq", "retrans→softirq", 0.5},
	{"net.conntrack", "net.drops", "conntrack→drops", 0.7},
	{"net.tcp.state", "net.conntrack", "tcpstate→conntrack", 0.5},
	{"net.tcp.state", "net.drops", "tcpstate→drops", 0.4},
	{"net.closewait", "net.conntrack", "closewait→conntrack", 0.5},
	{"net.drops", "net.tcp.retrans", "drops→retrans", 0.6},
}

// buildCausalDAG constructs a causal DAG from fired evidence across all domains.
// Returns nil if insufficient evidence to build a meaningful DAG.
func buildCausalDAG(result *model.AnalysisResult) *model.CausalDAG {
	// 1. Collect all fired evidence (strength >= 0.35) across all RCA entries
	firedMap := make(map[string]model.Evidence) // id → evidence
	for _, rca := range result.RCA {
		for _, e := range rca.EvidenceV2 {
			if e.Strength >= 0.35 {
				// Keep the strongest if duplicate IDs
				if existing, ok := firedMap[e.ID]; !ok || e.Strength > existing.Strength {
					firedMap[e.ID] = e
				}
			}
		}
	}

	if len(firedMap) < 2 {
		return nil
	}

	// 2. Create nodes for each fired evidence
	var nodes []model.CausalNode
	nodeSet := make(map[string]bool)
	for _, e := range firedMap {
		nodes = append(nodes, model.CausalNode{
			ID:          e.ID,
			Label:       e.Message,
			Type:        model.CausalIntermediate, // updated below
			Domain:      e.Domain,
			EvidenceIDs: []string{e.ID},
		})
		nodeSet[e.ID] = true
	}

	// 3. Apply rules to create edges where both from+to fired
	var edges []model.CausalEdge
	hasIncoming := make(map[string]bool)
	hasOutgoing := make(map[string]bool)
	for _, rule := range causalRules {
		if nodeSet[rule.from] && nodeSet[rule.to] {
			edges = append(edges, model.CausalEdge{
				From:   rule.from,
				To:     rule.to,
				Rule:   rule.rule,
				Weight: rule.weight,
			})
			hasOutgoing[rule.from] = true
			hasIncoming[rule.to] = true
		}
	}

	// 4. Classify nodes: root_cause (no incoming), symptom (no outgoing), else intermediate
	for i := range nodes {
		if !hasIncoming[nodes[i].ID] && hasOutgoing[nodes[i].ID] {
			nodes[i].Type = model.CausalRootCause
		} else if hasIncoming[nodes[i].ID] && !hasOutgoing[nodes[i].ID] {
			nodes[i].Type = model.CausalSymptom
		}
	}

	dag := &model.CausalDAG{
		Nodes: nodes,
		Edges: edges,
	}

	// 5. Build linear chain: find the highest-weight root→leaf path
	dag.LinearChain = linearize(dag, firedMap)

	return dag
}

// linearize finds the highest-weight path from a root to a leaf node
// and returns a human-readable " → "-joined string.
func linearize(dag *model.CausalDAG, firedMap map[string]model.Evidence) string {
	if len(dag.Edges) == 0 {
		// No edges: just list nodes by strength
		var parts []string
		for _, n := range dag.Nodes {
			parts = append(parts, n.Label)
		}
		return strings.Join(parts, " → ")
	}

	// Build adjacency list with weights
	type edge struct {
		to     string
		weight float64
		label  string
	}
	adj := make(map[string][]edge)
	for _, e := range dag.Edges {
		adj[e.From] = append(adj[e.From], edge{to: e.To, weight: e.Weight, label: e.Rule})
	}

	// Find root nodes
	var roots []string
	for _, n := range dag.Nodes {
		if n.Type == model.CausalRootCause {
			roots = append(roots, n.ID)
		}
	}
	// If no classified roots, use all nodes without incoming edges
	if len(roots) == 0 {
		incoming := make(map[string]bool)
		for _, e := range dag.Edges {
			incoming[e.To] = true
		}
		for _, n := range dag.Nodes {
			if !incoming[n.ID] {
				roots = append(roots, n.ID)
			}
		}
	}
	if len(roots) == 0 {
		return ""
	}

	// DFS to find highest-weight path
	type pathResult struct {
		path   []string
		weight float64
	}
	var bestPath pathResult

	var dfs func(node string, path []string, totalWeight float64, visited map[string]bool)
	dfs = func(node string, path []string, totalWeight float64, visited map[string]bool) {
		path = append(path, node)
		visited[node] = true

		extended := false
		for _, e := range adj[node] {
			if !visited[e.to] {
				extended = true
				dfs(e.to, path, totalWeight+e.weight, visited)
			}
		}

		if !extended {
			// Leaf: check if this path is the best
			if totalWeight > bestPath.weight || (totalWeight == bestPath.weight && len(path) > len(bestPath.path)) {
				cp := make([]string, len(path))
				copy(cp, path)
				bestPath = pathResult{path: cp, weight: totalWeight}
			}
		}

		visited[node] = false
	}

	for _, root := range roots {
		visited := make(map[string]bool)
		dfs(root, nil, 0, visited)
	}

	if len(bestPath.path) == 0 {
		return ""
	}

	// Convert IDs to labels
	labelMap := make(map[string]string)
	for _, n := range dag.Nodes {
		labelMap[n.ID] = n.Label
	}

	var parts []string
	for _, id := range bestPath.path {
		if label, ok := labelMap[id]; ok {
			parts = append(parts, label)
		} else {
			parts = append(parts, id)
		}
	}

	return strings.Join(parts, " → ")
}
