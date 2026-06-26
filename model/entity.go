// Entity graph types — the host-local dependency + ownership graph
// NEXTGEN Phase 3 introduces.
//
// Per NEXTGEN_RCA_ARCHITECTURE.md §3 "Entity Graph Layer", strong RCA
// on a multi-app host requires answering:
//
//   - who owns the resource?
//   - who is affected?
//   - who is upstream?
//   - who is downstream?
//   - what changed?
//
// The EntityGraph is the structure that lets Phase 4's verifier gates
// answer those questions in O(1) per lookup, instead of scanning every
// process/cgroup/socket in the snapshot.
//
// Phase 3 ships the structure populated with process + cgroup nodes.
// Future phases add: service nodes, socket nodes, dependency edges
// (cross-process socket links), mount nodes, container/pod nodes.

package model

// EntityKind classifies an Entity by what it represents. Verifier gates
// dispatch on Kind — e.g. "ownership-consistency" only applies if the
// claimed root Entity's Kind is one that can own a resource (process,
// cgroup, container).
type EntityKind string

const (
	EntityKindProcess    EntityKind = "process"
	EntityKindCgroup     EntityKind = "cgroup"
	EntityKindService    EntityKind = "service"     // systemd unit / aaPanel app / docker container — populated later
	EntityKindContainer  EntityKind = "container"   // docker / podman / lxc
	EntityKindPod        EntityKind = "pod"         // k8s pod (parent cgroup with multiple containers)
	EntityKindRuntime    EntityKind = "runtime"     // go/jvm/dotnet/node/python process group
	EntityKindMount      EntityKind = "mount"       // /var, /home, etc.
	EntityKindSocket     EntityKind = "socket"      // TCP/UDP endpoint
	EntityKindDependency EntityKind = "dependency"  // remote service this host depends on
	EntityKindHost       EntityKind = "host"        // the host itself, root of the graph
)

// Entity is one node in the host-local entity graph. Kept flat + JSON-
// serializable so it can ship over the fleet wire and survive replay.
//
// ID conventions (matches Fact.EntityID format):
//   "host"
//   "pid:1234"
//   "cgroup:/sys/fs/cgroup/system.slice/mongod.service"
//   "service:mongod"
//   "container:docker/abc123def"
//   "mount:/var/lib/mysql"
//   "socket:tcp/127.0.0.1:27017"
type Entity struct {
	// ID is the canonical entity identifier. Stable across ticks for
	// the lifetime of the entity. Required.
	ID string `json:"id"`

	// Kind buckets the entity for verifier dispatch.
	Kind EntityKind `json:"kind"`

	// Name is the human-readable label (process comm, service name,
	// cgroup leaf path, etc.). May be ambiguous; ID is the unique key.
	Name string `json:"name,omitempty"`

	// OwnerID is this entity's parent in the ownership hierarchy.
	// Empty for root entities (the host). Conventions:
	//   process    → cgroup or runtime
	//   cgroup     → parent cgroup, eventually "host"
	//   service    → cgroup
	//   container  → cgroup or pod
	//   pod        → host
	//   socket     → process (owning pid)
	//   mount      → host
	//
	// Resolving an OwnerID via EntityGraph.Lookup yields the parent
	// Entity, which has its own OwnerID, and so on up to "host".
	OwnerID string `json:"owner_id,omitempty"`

	// Tags carries free-form metadata: PID (when ID==cgroup), CPU%
	// rollup, RSS bytes, port number, mount type, etc. Verifier gates
	// read these for the ownership-consistency check.
	Tags map[string]string `json:"tags,omitempty"`
}

// EntityGraph is the snapshot-scoped collection of Entities and a fast
// lookup index. Built once per RCA tick by BuildEntityGraph(snap), read
// many times by detectors + verifier gates.
//
// Not thread-safe — graphs are owned by a single AnalysisResult and not
// shared across goroutines.
type EntityGraph struct {
	// Entities is the flat list, ordered for deterministic serialization.
	Entities []Entity `json:"entities"`

	// byID indexes Entities by ID for O(1) lookup. Not serialized;
	// rebuilt on deserialize via Reindex().
	byID map[string]int `json:"-"`
}

// NewEntityGraph returns an empty graph.
func NewEntityGraph() *EntityGraph {
	return &EntityGraph{
		byID: map[string]int{},
	}
}

// Add inserts an entity into the graph. If an entity with the same ID
// already exists, the new one REPLACES it — callers must dedupe
// upstream if that's not desired.
func (g *EntityGraph) Add(e Entity) {
	if g.byID == nil {
		g.byID = map[string]int{}
	}
	if i, ok := g.byID[e.ID]; ok {
		g.Entities[i] = e
		return
	}
	g.byID[e.ID] = len(g.Entities)
	g.Entities = append(g.Entities, e)
}

// Lookup returns the entity with the given ID, or nil if absent.
// O(1).
func (g *EntityGraph) Lookup(id string) *Entity {
	if g == nil || g.byID == nil {
		return nil
	}
	i, ok := g.byID[id]
	if !ok {
		return nil
	}
	return &g.Entities[i]
}

// Owner walks one step up the ownership chain. Returns nil if entity
// is absent, has no owner, or owner has been pruned.
func (g *EntityGraph) Owner(id string) *Entity {
	e := g.Lookup(id)
	if e == nil || e.OwnerID == "" {
		return nil
	}
	return g.Lookup(e.OwnerID)
}

// AncestorChain returns the chain of ancestors from `id` (exclusive)
// up to the root. Empty slice if entity is absent or has no owner.
// Stops at the first cycle (defensive — graphs should be acyclic but
// pathological cgroup setups have produced cycles in the wild).
func (g *EntityGraph) AncestorChain(id string) []*Entity {
	if g == nil {
		return nil
	}
	visited := map[string]bool{id: true}
	var chain []*Entity
	for cur := g.Owner(id); cur != nil; cur = g.Owner(cur.ID) {
		if visited[cur.ID] {
			break // cycle guard
		}
		visited[cur.ID] = true
		chain = append(chain, cur)
		if len(chain) > 64 {
			break // pathological depth guard
		}
	}
	return chain
}

// Reindex rebuilds the byID map. Call after deserializing an EntityGraph
// from JSON or after bulk-appending to Entities without using Add().
//
// Note: The index rebuild is O(n) by design. This is acceptable since
// Reindex() is called only on deserialization and bulk-add paths, not on
// hot lookup paths. Only optimize this if profiling shows it to be a
// bottleneck (YAGNI).
func (g *EntityGraph) Reindex() {
	if g == nil {
		return
	}
	g.byID = make(map[string]int, len(g.Entities))
	for i, e := range g.Entities {
		g.byID[e.ID] = i
	}
}

// Len returns the number of entities in the graph.
func (g *EntityGraph) Len() int {
	if g == nil {
		return 0
	}
	return len(g.Entities)
}
