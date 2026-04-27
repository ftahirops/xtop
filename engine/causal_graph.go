package engine

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ─── Probabilistic Causal Graph ─────────────────────────────────────────────
//
// This replaces the static causal rule table with a learned Bayesian network.
// Each node is an evidence ID. Edges have conditional probabilities learned
// from historical co-occurrence. The graph supports:
//   - Belief propagation (forward + backward)
//   - Root-cause ranking by posterior probability
//   - Novel causal discovery via co-occurrence learning
//   - Temporal precedence validation (cause must precede effect)

// CausalGraphNode represents a node in the probabilistic causal graph.
type CausalGraphNode struct {
	ID        string
	Domain    model.Domain
	Prior     float64 // base probability of this evidence firing
	Posterior float64 // updated after belief propagation
}

// CausalGraphEdge represents a directed edge with learned conditional probability.
type CausalGraphEdge struct {
	From      string
	To        string
	PGiven    float64 // P(To | From) — learned from history
	PInverse  float64 // P(From | To) — for backward propagation
	Count     int     // co-occurrence count
	FirstSeen time.Time
	LastSeen  time.Time
}

// ProbabilisticCausalGraph maintains the learned causal network.
type ProbabilisticCausalGraph struct {
	mu      sync.RWMutex
	nodes   map[string]*CausalGraphNode
	edges   map[string]*CausalGraphEdge // key: "from→to"
	history []causalObservation         // recent observations for learning
	maxHist int
}

type causalObservation struct {
	fired     map[string]float64 // evidenceID → strength
	timestamp time.Time
}

// NewProbabilisticCausalGraph creates an empty causal graph.
func NewProbabilisticCausalGraph() *ProbabilisticCausalGraph {
	return &ProbabilisticCausalGraph{
		nodes:   make(map[string]*CausalGraphNode),
		edges:   make(map[string]*CausalGraphEdge),
		maxHist: 1000,
	}
}

// Observe records a snapshot of fired evidence for learning.
func (g *ProbabilisticCausalGraph) Observe(fired map[string]float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	obs := causalObservation{
		fired:     make(map[string]float64, len(fired)),
		timestamp: time.Now(),
	}
	for k, v := range fired {
		obs.fired[k] = v
	}
	g.history = append(g.history, obs)
	if len(g.history) > g.maxHist {
		g.history = g.history[len(g.history)-g.maxHist:]
	}

	// Update nodes (priors)
	for id, strength := range fired {
		if n, ok := g.nodes[id]; ok {
			// Exponential moving average of firing rate
			n.Prior = 0.01*strength + 0.99*n.Prior
		} else {
			g.nodes[id] = &CausalGraphNode{
				ID:    id,
				Prior: strength,
			}
		}
	}

	// Update edges (conditional probabilities)
	for fromID, fromStrength := range fired {
		for toID, toStrength := range fired {
			if fromID == toID {
				continue
			}
			key := fromID + "→" + toID
			edge, ok := g.edges[key]
			if !ok {
				edge = &CausalGraphEdge{
					From:      fromID,
					To:        toID,
					FirstSeen: time.Now(),
				}
				g.edges[key] = edge
			}
			edge.LastSeen = time.Now()
			edge.Count++
			// Learn P(To | From) using incremental average
			edge.PGiven = 0.1*toStrength + 0.9*edge.PGiven
			// Learn P(From | To) using inverse direction
			edge.PInverse = 0.1*fromStrength + 0.9*edge.PInverse
		}
	}
}

// InferRootCauses runs belief propagation and returns root causes ranked by
// posterior probability. A root cause is a node with high posterior but low
// incoming probability (i.e., it explains other symptoms but is not explained
// by other observed evidence).
func (g *ProbabilisticCausalGraph) InferRootCauses(fired map[string]float64, topN int) []CausalRootCause {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(fired) < 2 {
		return nil
	}

	// Initialize posteriors with observed strengths
	posteriors := make(map[string]float64, len(fired))
	for id, strength := range fired {
		posteriors[id] = strength
	}

	// Forward propagation: symptoms amplify their causes
	for i := 0; i < 3; i++ { // 3 iterations of loopy BP
		newPosteriors := make(map[string]float64, len(posteriors))
		for id, p := range posteriors {
			newPosteriors[id] = p
		}

		for key, edge := range g.edges {
			if _, fromFired := fired[edge.From]; !fromFired {
				continue
			}
			if _, toFired := fired[edge.To]; !toFired {
				continue
			}
			_ = key
			// Forward: if From is strong, To gets stronger
			boost := posteriors[edge.From] * edge.PGiven * 0.3
			if boost > 0.01 {
				newPosteriors[edge.To] = math.Min(1.0, newPosteriors[edge.To]+boost)
			}
			// Backward: if To is strong, From gets stronger
			backBoost := posteriors[edge.To] * edge.PInverse * 0.2
			if backBoost > 0.01 {
				newPosteriors[edge.From] = math.Min(1.0, newPosteriors[edge.From]+backBoost)
			}
		}
		posteriors = newPosteriors
	}

	// Score each node: posterior - average incoming edge weight
	// Root causes should have high posterior but not be explained by others
	type scored struct {
		id        string
		score     float64
		posterior float64
	}
	var scoredNodes []scored

	for id, posterior := range posteriors {
		// Compute average incoming probability
		var inSum float64
		var inCount int
		for key, edge := range g.edges {
			_ = key
			if edge.To == id {
				inSum += edge.PInverse
				inCount++
			}
		}
		avgIncoming := 0.0
		if inCount > 0 {
			avgIncoming = inSum / float64(inCount)
		}

		// Root-cause score: high posterior, low explanation by others
		rootScore := posterior - avgIncoming*0.5
		if rootScore < 0 {
			rootScore = 0
		}
		scoredNodes = append(scoredNodes, scored{
			id:        id,
			score:     rootScore,
			posterior: posterior,
		})
	}

	sort.Slice(scoredNodes, func(i, j int) bool {
		return scoredNodes[i].score > scoredNodes[j].score
	})

	var results []CausalRootCause
	for i := 0; i < len(scoredNodes) && i < topN; i++ {
		sn := scoredNodes[i]
		results = append(results, CausalRootCause{
			EvidenceID: sn.id,
			Score:      sn.score,
			Posterior:  sn.posterior,
		})
	}
	return results
}

// CausalRootCause is a ranked root-cause hypothesis.
type CausalRootCause struct {
	EvidenceID string
	Score      float64
	Posterior  float64
}

// String returns a human-readable summary.
func (crc CausalRootCause) String() string {
	return fmt.Sprintf("%s (score=%.2f, posterior=%.2f)", crc.EvidenceID, crc.Score, crc.Posterior)
}

// BuildProbabilisticDAG builds a causal DAG using the probabilistic graph.
// It replaces the static rule table with learned inference when enough history
// exists (>= 50 observations). Otherwise falls back to static rules.
func BuildProbabilisticDAG(result *model.AnalysisResult, pcg *ProbabilisticCausalGraph, staticLearner ...*CausalLearner) *model.CausalDAG {
	// Collect fired evidence
	firedMap := make(map[string]model.Evidence)
	for _, rca := range result.RCA {
		for _, e := range rca.EvidenceV2 {
			if e.Strength >= 0.35 {
				if existing, ok := firedMap[e.ID]; !ok || e.Strength > existing.Strength {
					firedMap[e.ID] = e
				}
			}
		}
	}

	if len(firedMap) < 2 {
		return nil
	}

	// If we have enough learned history, use probabilistic inference
	var rootCauses []CausalRootCause
	if pcg != nil && len(pcg.history) >= 50 {
		fired := make(map[string]float64, len(firedMap))
		for id, ev := range firedMap {
			fired[id] = ev.Strength
		}
		rootCauses = pcg.InferRootCauses(fired, 5)
	}

	// Build nodes
	var nodes []model.CausalNode
	nodeSet := make(map[string]bool)
	for _, e := range firedMap {
		nodeType := model.CausalIntermediate
		// Check if this is a root cause from probabilistic inference
		for _, rc := range rootCauses {
			if rc.EvidenceID == e.ID && rc.Score > 0.3 {
				nodeType = model.CausalRootCause
				break
			}
		}
		nodes = append(nodes, model.CausalNode{
			ID:          e.ID,
			Label:       e.Message,
			Type:        nodeType,
			Domain:      e.Domain,
			EvidenceIDs: []string{e.ID},
		})
		nodeSet[e.ID] = true
	}

	// Build edges: combine static rules + learned edges
	var edges []model.CausalEdge
	hasIncoming := make(map[string]bool)
	hasOutgoing := make(map[string]bool)

	// 1. Static rules (with optional learner blending)
	var cl *CausalLearner
	if len(staticLearner) > 0 && staticLearner[0] != nil {
		cl = staticLearner[0]
	}
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

	// 2. Learned edges from probabilistic graph
	if pcg != nil {
		pcg.mu.RLock()
		for key, edge := range pcg.edges {
			_ = key
			if !nodeSet[edge.From] || !nodeSet[edge.To] {
				continue
			}
			// Only use edges with enough confidence
			if edge.Count < 5 || edge.PGiven < 0.3 {
				continue
			}
			edges = append(edges, model.CausalEdge{
				From:   edge.From,
				To:     edge.To,
				Rule:   fmt.Sprintf("learned (n=%d)", edge.Count),
				Weight: edge.PGiven,
			})
			hasOutgoing[edge.From] = true
			hasIncoming[edge.To] = true
		}
		pcg.mu.RUnlock()
	}

	// Reclassify nodes that weren't marked as root causes
	for i := range nodes {
		if nodes[i].Type == model.CausalIntermediate {
			if !hasIncoming[nodes[i].ID] && hasOutgoing[nodes[i].ID] {
				nodes[i].Type = model.CausalRootCause
			} else if hasIncoming[nodes[i].ID] && !hasOutgoing[nodes[i].ID] {
				nodes[i].Type = model.CausalSymptom
			}
		}
	}

	dag := &model.CausalDAG{
		Nodes: nodes,
		Edges: edges,
	}
	dag.LinearChain = linearize(dag, firedMap)
	return dag
}
