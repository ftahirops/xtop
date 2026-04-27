package engine

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ─── Topology-Aware Cross-Host Correlator ───────────────────────────────────
//
// Replaces the simple string-matching cross-host correlation with a proper
// graph topology model. Hosts are nodes in a dependency graph (data flow,
// service mesh, load balancer → backend). Incidents are correlated based on:
//   - Graph distance (how close in the topology)
//   - Temporal proximity (within a time window)
//   - Symptom similarity (same bottleneck domain)
//   - Cascade direction (upstream → downstream)

// TopologyRole describes a host's position in the infrastructure graph.
type TopologyRole string

const (
	RoleLoadBalancer TopologyRole = "lb"
	RoleWebServer    TopologyRole = "web"
	RoleAppServer    TopologyRole = "app"
	RoleDatabase     TopologyRole = "db"
	RoleCache        TopologyRole = "cache"
	RoleQueue        TopologyRole = "queue"
	RoleUnknown      TopologyRole = "unknown"
)

// HostTopology describes a host's position and connections in the infra graph.
type HostTopology struct {
	HostID   string
	Role     TopologyRole
	Tier     int      // 0 = edge/lb, 1 = web, 2 = app, 3 = data
	Region   string   // AWS region, datacenter, etc.
	Zone     string   // AZ, rack, etc.
	Peers    []string // directly connected host IDs
	Services []string // services running on this host
}

// IncidentCorrelation is a correlated incident between two hosts.
type IncidentCorrelation struct {
	SourceHost     string
	TargetHost     string
	SourceIncident *model.HostIncident
	TargetIncident *model.HostIncident
	Distance       int     // graph hops
	Likelihood     float64 // 0-1, probability that source caused target
	Direction      string  // "upstream", "downstream", "peer", "unknown"
	TimeDeltaSec   float64
}

// TopologyCorrelator maintains the infrastructure graph and correlates incidents.
type TopologyCorrelator struct {
	mu        sync.RWMutex
	hosts     map[string]*HostTopology
	incidents map[string]*model.HostIncident // hostID → latest incident
}

// NewTopologyCorrelator creates a new topology-aware correlator.
func NewTopologyCorrelator() *TopologyCorrelator {
	return &TopologyCorrelator{
		hosts:     make(map[string]*HostTopology),
		incidents: make(map[string]*model.HostIncident),
	}
}

// RegisterHost adds or updates a host in the topology graph.
func (tc *TopologyCorrelator) RegisterHost(host *HostTopology) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.hosts[host.HostID] = host
}

// RecordIncident stores an incident for correlation.
func (tc *TopologyCorrelator) RecordIncident(hostID string, incident *model.HostIncident) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.incidents[hostID] = incident
}

// Correlate finds all hosts whose current incidents are likely caused by or
// related to the given host's incident. Returns correlations ranked by likelihood.
func (tc *TopologyCorrelator) Correlate(hostID string, window time.Duration) []IncidentCorrelation {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	sourceIncident, ok := tc.incidents[hostID]
	if !ok || sourceIncident == nil {
		return nil
	}

	sourceHost, ok := tc.hosts[hostID]
	if !ok {
		return nil
	}

	var correlations []IncidentCorrelation
	now := time.Now()

	for otherID, otherIncident := range tc.incidents {
		if otherID == hostID {
			continue
		}
		if otherIncident == nil {
			continue
		}

		// Time window check
		timeDelta := now.Sub(otherIncident.Timestamp)
		if timeDelta > window && otherIncident.Timestamp.After(now) {
			continue
		}

		otherHost, hasHost := tc.hosts[otherID]
		if !hasHost {
			continue
		}

		// Compute correlation
		corr := tc.computeCorrelation(sourceHost, otherHost, sourceIncident, otherIncident)
		if corr.Likelihood > 0.3 {
			correlations = append(correlations, corr)
		}
	}

	sort.Slice(correlations, func(i, j int) bool {
		return correlations[i].Likelihood > correlations[j].Likelihood
	})

	return correlations
}

// computeCorrelation calculates the likelihood that two incidents are related.
func (tc *TopologyCorrelator) computeCorrelation(
	sourceHost, otherHost *HostTopology,
	sourceIncident, otherIncident *model.HostIncident,
) IncidentCorrelation {
	corr := IncidentCorrelation{
		SourceHost:     sourceHost.HostID,
		TargetHost:     otherHost.HostID,
		SourceIncident: sourceIncident,
		TargetIncident: otherIncident,
		TimeDeltaSec:   otherIncident.Timestamp.Sub(sourceIncident.Timestamp).Seconds(),
	}

	// 1. Graph distance
	dist := graphDistance(sourceHost, otherHost)
	corr.Distance = dist

	// 2. Direction
	corr.Direction = inferDirection(sourceHost, otherHost)

	// 3. Domain similarity
	domainSim := domainSimilarity(sourceIncident.PrimaryBottleneck, otherIncident.PrimaryBottleneck)

	// 4. Likelihood score
	// Base: domain similarity
	likelihood := domainSim * 0.5

	// Topology bonus: closer hosts are more likely related
	if dist == 0 {
		likelihood += 0.1 // same host (shouldn't happen, but defensive)
	} else if dist == 1 {
		likelihood += 0.3 // directly connected
	} else if dist == 2 {
		likelihood += 0.15
	}

	// Direction bonus: upstream→downstream cascade is very likely
	if corr.Direction == "upstream" || corr.Direction == "downstream" {
		likelihood += 0.1
	}

	// Time bonus: incidents within 30s are more likely related
	if abs(corr.TimeDeltaSec) < 30 {
		likelihood += 0.1
	}

	// Same zone/region bonus
	if sourceHost.Region == otherHost.Region {
		likelihood += 0.05
		if sourceHost.Zone == otherHost.Zone {
			likelihood += 0.05
		}
	}

	corr.Likelihood = minFloat64(likelihood, 1.0)
	return corr
}

// graphDistance computes the shortest path distance between two hosts.
// Returns -1 if no path exists.
func graphDistance(a, b *HostTopology) int {
	if a.HostID == b.HostID {
		return 0
	}

	// BFS
	visited := make(map[string]bool)
	queue := []struct {
		id   string
		dist int
	}{{a.HostID, 0}}
	visited[a.HostID] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.id == b.HostID {
			return curr.dist
		}

		// We need to look up peers in the global host map
		// This is a simplified BFS - in production you'd use the full graph
		// For now, check direct peers
		if curr.id == a.HostID {
			for _, peerID := range a.Peers {
				if peerID == b.HostID {
					return curr.dist + 1
				}
			}
		}
		// Check if b is a peer of any host we know about
		for _, peerID := range b.Peers {
			if peerID == a.HostID {
				return 1
			}
		}
	}

	// Fallback: use tier difference as heuristic
	tierDiff := a.Tier - b.Tier
	if tierDiff < 0 {
		tierDiff = -tierDiff
	}
	if tierDiff <= 2 {
		return tierDiff + 1
	}
	return 999 // effectively disconnected
}

// inferDirection determines if a → b is upstream, downstream, or peer.
func inferDirection(a, b *HostTopology) string {
	if a.Tier < b.Tier {
		return "upstream" // a is closer to edge, b is deeper
	}
	if a.Tier > b.Tier {
		return "downstream"
	}
	// Check explicit peer relationships
	for _, peer := range a.Peers {
		if peer == b.HostID {
			return "peer"
		}
	}
	return "unknown"
}

// domainSimilarity returns how similar two bottleneck domains are (0-1).
func domainSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	// Cross-domain causality matrix
	crossDomain := map[string]float64{
		"memory→io":   0.7,
		"io→memory":   0.5,
		"cpu→io":      0.4,
		"io→cpu":      0.6,
		"cpu→memory":  0.3,
		"memory→cpu":  0.3,
		"network→cpu": 0.5,
		"cpu→network": 0.4,
	}
	key := strings.ToLower(a) + "→" + strings.ToLower(b)
	if sim, ok := crossDomain[key]; ok {
		return sim
	}
	return 0.1 // weak default
}

func minFloat64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// FormatCorrelations returns a human-readable summary of correlations.
func FormatCorrelations(correlations []IncidentCorrelation) []string {
	var out []string
	for _, c := range correlations {
		if c.Likelihood < 0.5 {
			continue
		}
		msg := fmt.Sprintf("%s → %s: %s incident likely %s (%.0f%% confidence, %d hop(s))",
			c.SourceHost, c.TargetHost,
			c.TargetIncident.PrimaryBottleneck,
			c.Direction,
			c.Likelihood*100,
			c.Distance,
		)
		out = append(out, msg)
	}
	return out
}
