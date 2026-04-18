package engine

import (
	"strings"
	"sync"

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
	// FIX: low available memory causes OOM kills, not reverse
	{"mem.available.low", "mem.oom.kills", "lowmem→oom", 0.95},

	// Cross-domain: memory → IO
	{"mem.swap.activity", "io.psi", "swap→iopsi", 0.7},
	{"mem.swap.activity", "io.disk.latency", "swap→iolatency", 0.65},
	{"mem.reclaim.direct", "io.disk.latency", "reclaim→iolatency", 0.6},
	{"mem.major.faults", "io.disk.latency", "faults→iolatency", 0.5},

	// CPU domain
	{"cpu.busy", "cpu.runqueue", "cpubusy→runqueue", 0.85},
	{"cpu.busy", "cpu.psi", "cpubusy→psi", 0.8},
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
	{"net.tcp.timewait", "net.conntrack", "timewait→conntrack", 0.5},
	{"net.tcp.synsent", "net.drops", "synsent→drops", 0.4},
	{"net.closewait", "net.conntrack", "closewait→conntrack", 0.5},
	{"net.drops", "net.tcp.retrans", "drops→retrans", 0.6},
	{"net.conntrack", "net.conntrack.drops", "conntrack→ctdrops", 0.9},
	{"net.conntrack", "net.conntrack.insertfail", "conntrack→ctinsertfail", 0.9},
	{"net.conntrack.growth", "net.conntrack", "ctgrowth→conntrack", 0.7},
	{"net.conntrack.drops", "net.tcp.retrans", "ctdrops→retrans", 0.6},

	// Security domain
	{"sec.synflood", "net.conntrack.growth", "synflood→ctgrowth", 0.9},
	{"sec.synflood", "net.drops", "synflood→drops", 0.8},
	{"sec.portscan", "net.sentinel.resets", "portscan→resets", 0.85},
	{"sec.dns.tunnel", "sec.dns.anomaly", "tunnel→dnsanomaly", 0.7},
	{"sec.lateral", "sec.outbound.exfil", "lateral→exfil", 0.75},
	{"sec.beacon", "sec.outbound.exfil", "beacon→exfil", 0.6},
	{"sec.tcp.flags", "sec.portscan", "tcpflags→portscan", 0.8},
	{"sec.synflood", "cpu.busy", "synflood→cpubusy", 0.5},

	// Memory extended
	{"mem.psi.acceleration", "mem.reclaim.direct", "psiaccel→reclaim", 0.85},
	{"mem.slab.leak", "mem.available.low", "slableak→lowmem", 0.7},
	{"mem.alloc.stall", "mem.psi", "allocstall→mempsi", 0.8},
	{"mem.swap.in", "io.disk.latency", "swapin→iolatency", 0.7},

	// CPU extended — FIX: disk latency causes iowait, not reverse
	{"io.disk.latency", "cpu.iowait", "iolatency→iowait", 0.8},
	{"io.disk.latency", "io.psi", "iolatency→iopsi", 0.7},
	{"cpu.irq.imbalance", "net.drops", "irqimbalance→drops", 0.6},

	// Network extended
	{"net.drops.rx", "net.tcp.retrans", "rxdrops→retrans", 0.7},
	{"net.tcp.synsent", "net.tcp.attemptfails", "synsent→attemptfails", 0.8},
	{"net.ephemeral", "net.tcp.attemptfails", "ephemeral→attemptfails", 0.85},
	{"net.tcp.resets", "net.tcp.retrans", "resets→retrans", 0.5},
	{"net.tcp.timewait", "net.ephemeral", "timewait→ephemeral", 0.7},
	{"net.udp.errors", "net.drops", "udperrors→drops", 0.4},

	// FD exhaustion — NEW evidence type
	{"proc.fd.exhaustion", "net.tcp.retrans", "fdexhaust→retrans", 0.8},
	{"proc.fd.exhaustion", "net.drops", "fdexhaust→drops", 0.7},
	{"proc.fd.exhaustion", "io.disk.latency", "fdexhaust→iolatency", 0.5},

	// .NET domain
	{"dotnet.gc.pause", "cpu.runqueue", "gcpause→runqueue", 0.7},
	{"dotnet.alloc.storm", "mem.reclaim.direct", "allocstorm→reclaim", 0.65},
	{"dotnet.alloc.storm", "dotnet.gc.pause", "allocstorm→gcpause", 0.8},
	{"dotnet.threadpool.queue", "dotnet.gc.pause", "tpqueue→gcpause", 0.5},

	// JVM domain
	{"jvm.gc.pause", "cpu.runqueue", "jvmgcpause→runqueue", 0.7},
	{"jvm.heap.pressure", "mem.reclaim.direct", "jvmheap→reclaim", 0.6},
	{"jvm.heap.pressure", "jvm.gc.pause", "jvmheap→gcpause", 0.85},

	// Proxmox VM domain
	{"pve.vm.throttle", "cpu.runqueue", "vmthrottle→runqueue", 0.7},
	{"pve.vm.oom", "mem.available.low", "vmoom→lowmem", 0.9},
	{"pve.vm.swap", "io.psi", "vmswap→iopsi", 0.65},
	{"pve.vm.memlimit", "pve.vm.swap", "vmmemlimit→vmswap", 0.8},
	{"pve.vm.memlimit", "pve.vm.oom", "vmmemlimit→vmoom", 0.85},
	{"pve.vm.cpupsi", "pve.vm.throttle", "vmcpupsi→vmthrottle", 0.7},
	{"pve.vm.mempsi", "pve.vm.swap", "vmmempsi→vmswap", 0.6},
}

// buildCausalDAG constructs a causal DAG from fired evidence across all domains.
// Returns nil if insufficient evidence to build a meaningful DAG.
// If learner is non-nil, hardcoded rule weights are blended with learned weights.
func buildCausalDAG(result *model.AnalysisResult, learner ...*CausalLearner) *model.CausalDAG {
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
	var cl *CausalLearner
	if len(learner) > 0 && learner[0] != nil {
		cl = learner[0]
	}

	var edges []model.CausalEdge
	hasIncoming := make(map[string]bool)
	hasOutgoing := make(map[string]bool)
	for _, rule := range causalRules {
		if nodeSet[rule.from] && nodeSet[rule.to] {
			w := rule.weight
			if cl != nil {
				w = cl.LearnedWeight(rule.rule, rule.weight, rule.from, rule.to)
			}
			edges = append(edges, model.CausalEdge{
				From:   rule.from,
				To:     rule.to,
				Rule:   rule.rule,
				Weight: w,
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

	// Depth limit prevents infinite loops if causalRules ever contains cycles
	// (e.g., net.drops → net.tcp.retrans → net.softirq → net.drops).
	maxDepth := len(dag.Nodes) + 2

	var dfs func(node string, path []string, totalWeight float64, visited map[string]bool)
	dfs = func(node string, path []string, totalWeight float64, visited map[string]bool) {
		if len(path) >= maxDepth {
			return // cycle safeguard
		}
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

// CausalLearner tracks how often causal rules' predictions hold true
// and learns co-occurrence patterns from observed evidence.
type CausalLearner struct {
	mu    sync.RWMutex
	stats map[string]*causalRuleStats

	// Co-occurrence learning: from → to → count
	coOccurrence map[string]map[string]int
	totalSamples int
}

type causalRuleStats struct {
	BothFired   int64
	CauseFirst  int64
	EffectFirst int64
}

// NewCausalLearner creates a causal learning tracker.
func NewCausalLearner() *CausalLearner {
	return &CausalLearner{
		stats:        make(map[string]*causalRuleStats),
		coOccurrence: make(map[string]map[string]int),
	}
}

// Observe records whether a causal rule's prediction held for this tick.
func (cl *CausalLearner) Observe(rule string, causeFired, effectFired bool, causeFirst bool) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	s, ok := cl.stats[rule]
	if !ok {
		s = &causalRuleStats{}
		cl.stats[rule] = s
	}
	if causeFired && effectFired {
		s.BothFired++
		if causeFirst {
			s.CauseFirst++
		} else {
			s.EffectFirst++
		}
	}
}

// ObserveCoOccurrence records which evidence IDs fired together in a single tick.
// This builds a co-occurrence matrix used to supplement hardcoded causal weights.
func (cl *CausalLearner) ObserveCoOccurrence(firedEvidence []string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.totalSamples++
	for i, a := range firedEvidence {
		for j, b := range firedEvidence {
			if i != j {
				if cl.coOccurrence[a] == nil {
					cl.coOccurrence[a] = make(map[string]int)
				}
				cl.coOccurrence[a][b]++
			}
		}
	}
}

// CoOccurrenceWeight returns the learned co-occurrence weight between two evidence IDs.
// Returns 0 if insufficient data.
func (cl *CausalLearner) CoOccurrenceWeight(from, to string) float64 {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	if cl.totalSamples < 20 {
		return 0
	}
	return float64(cl.coOccurrence[from][to]) / float64(cl.totalSamples)
}

// LearnedWeight returns a blended weight: 70% hardcoded + 30% observed.
// The observed component blends rule-level causal ordering with co-occurrence data.
// Returns the hardcoded weight if insufficient observations (<20).
func (cl *CausalLearner) LearnedWeight(rule string, hardcodedWeight float64, from, to string) float64 {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	// Rule-level directional observation
	s, ruleOK := cl.stats[rule]
	hasRule := ruleOK && s.BothFired >= 20

	// Co-occurrence observation
	hasCoOcc := cl.totalSamples >= 20

	if !hasRule && !hasCoOcc {
		return hardcodedWeight
	}

	var observedWeight float64
	if hasRule && hasCoOcc {
		ruleWeight := float64(s.CauseFirst) / float64(s.BothFired)
		coOccWeight := float64(cl.coOccurrence[from][to]) / float64(cl.totalSamples)
		// Blend rule direction (60%) with co-occurrence frequency (40%)
		observedWeight = 0.6*ruleWeight + 0.4*coOccWeight
	} else if hasRule {
		observedWeight = float64(s.CauseFirst) / float64(s.BothFired)
	} else {
		observedWeight = float64(cl.coOccurrence[from][to]) / float64(cl.totalSamples)
	}

	return 0.7*hardcodedWeight + 0.3*observedWeight
}
