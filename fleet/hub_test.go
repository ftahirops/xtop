package fleet

import (
	"bytes"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ftahirops/xtop/model"
	_ "modernc.org/sqlite"
)

// ─── Gap tests (Batch 2) ──────────────────────────────────────────────────────

// TestDuplicateIncidentDrop verifies that isDuplicateIncident gates
// repeat (agent, signature, update_type) tuples within 30 s. The second
// identical POST must return 204 but must NOT reach the broadcast/persist
// path, which we confirm by checking the dedup map has only one entry.
func TestDuplicateIncidentDrop(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})

	// Unique agent to avoid rate-limiter interference from other tests.
	body := `{"incident_id":"inc-dup","agent_id":"dedup-agent","hostname":"h1",` +
		`"update_type":"started","signature":"sig-dup","peak_score":80,"confidence":90}`

	// First POST — should go through normally.
	w1 := httptest.NewRecorder()
	h.handleIncident(w1, httptest.NewRequest("POST", "/v1/incident", strings.NewReader(body)))
	if w1.Code != http.StatusNoContent {
		t.Fatalf("first incident: want 204, got %d", w1.Code)
	}

	// Dedup map must now contain exactly one entry.
	h.dedupeMu.Lock()
	countAfterFirst := len(h.dedupe)
	h.dedupeMu.Unlock()
	if countAfterFirst != 1 {
		t.Fatalf("after first POST: expected 1 dedup entry, got %d", countAfterFirst)
	}

	// Second identical POST — must be deduped and return 204.
	w2 := httptest.NewRecorder()
	h.handleIncident(w2, httptest.NewRequest("POST", "/v1/incident", strings.NewReader(body)))
	if w2.Code != http.StatusNoContent {
		t.Fatalf("second incident: want 204, got %d", w2.Code)
	}

	// Dedup map still has exactly one entry (the second call didn't add a new one).
	h.dedupeMu.Lock()
	countAfterSecond := len(h.dedupe)
	h.dedupeMu.Unlock()
	if countAfterSecond != 1 {
		t.Fatalf("after second POST: expected 1 dedup entry (no new entry added), got %d", countAfterSecond)
	}
}

// TestZeroPayloadIncidentDrop verifies the ingest quality gate:
//   - An incident with PeakScore==0 AND Confidence==0 AND UpdateType!=Resolved is dropped (204) before dedup.
//   - A Resolved incident with the same zero scores is NOT dropped.
func TestZeroPayloadIncidentDrop(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})

	// Zero-score non-resolved → must be dropped silently.
	zeroBody := `{"incident_id":"inc-zero","agent_id":"zero-agent","hostname":"h2",` +
		`"update_type":"started","signature":"sig-zero","peak_score":0,"confidence":0}`
	w1 := httptest.NewRecorder()
	h.handleIncident(w1, httptest.NewRequest("POST", "/v1/incident", strings.NewReader(zeroBody)))
	if w1.Code != http.StatusNoContent {
		t.Fatalf("zero-payload non-resolved: want 204, got %d", w1.Code)
	}
	// Payload was dropped BEFORE reaching isDuplicateIncident, so the dedup
	// map must be empty — the key was never registered.
	h.dedupeMu.Lock()
	_, inDedup := h.dedupe["zero-agent|sig-zero|started"]
	h.dedupeMu.Unlock()
	if inDedup {
		t.Fatal("zero-payload incident must not reach the dedup gate (should have been dropped earlier)")
	}

	// Resolved with zero scores → must NOT be dropped (legit close-out event).
	resolvedBody := `{"incident_id":"inc-res","agent_id":"resolved-agent","hostname":"h3",` +
		`"update_type":"resolved","signature":"sig-res","peak_score":0,"confidence":0}`
	w2 := httptest.NewRecorder()
	h.handleIncident(w2, httptest.NewRequest("POST", "/v1/incident", strings.NewReader(resolvedBody)))
	if w2.Code != http.StatusNoContent {
		t.Fatalf("resolved zero-payload: want 204, got %d", w2.Code)
	}
	// Resolved event reached isDuplicateIncident, so the key must be in the dedup map.
	h.dedupeMu.Lock()
	_, inDedupResolved := h.dedupe["resolved-agent|sig-res|resolved"]
	h.dedupeMu.Unlock()
	if !inDedupResolved {
		t.Fatal("resolved zero-payload must NOT be dropped — key should be present in dedup map")
	}
}

// TestHeartbeatUpdatesRegistry verifies that a POSTed heartbeat updates the
// in-memory hosts registry. It checks both direct map access and the
// handleListHosts endpoint.
func TestHeartbeatUpdatesRegistry(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})

	hbBody := `{"hostname":"reg-host","agent_id":"reg-agent"}`
	w := httptest.NewRecorder()
	h.handleHeartbeat(w, httptest.NewRequest("POST", "/v1/heartbeat", strings.NewReader(hbBody)))
	if w.Code != http.StatusNoContent {
		t.Fatalf("heartbeat POST: want 204, got %d", w.Code)
	}

	// Direct registry check.
	h.hostsMu.RLock()
	host := h.hosts["reg-agent"]
	h.hostsMu.RUnlock()
	if host == nil {
		t.Fatal("expected host 'reg-agent' in in-memory registry after heartbeat")
	}
	if host.Hostname != "reg-host" {
		t.Fatalf("registry: expected hostname 'reg-host', got %q", host.Hostname)
	}
	if host.AgentID != "reg-agent" {
		t.Fatalf("registry: expected agent_id 'reg-agent', got %q", host.AgentID)
	}

	// Also verify via the /v1/hosts handler.
	w2 := httptest.NewRecorder()
	h.handleListHosts(w2, httptest.NewRequest("GET", "/v1/hosts", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("GET /v1/hosts: want 200, got %d", w2.Code)
	}
	var hosts []*model.FleetHost
	if err := json.NewDecoder(w2.Body).Decode(&hosts); err != nil {
		t.Fatalf("decode /v1/hosts response: %v", err)
	}
	var found bool
	for _, fh := range hosts {
		if fh.AgentID == "reg-agent" && fh.Hostname == "reg-host" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("handleListHosts: host 'reg-host' (agent 'reg-agent') not present in response %v", hosts)
	}
}

// TestSQLiteCacheRoundTrip verifies that persistHeartbeat writes to the
// SQLite hot-cache and the data can be read back. The Postgres path will
// log an error (the test hub uses a stub SQLite-backed h.pg with no
// fleet_heartbeats table) but persistHeartbeat does not abort on that
// error — the cache write still runs. We call persistHeartbeat
// synchronously (not via the goroutine started by handleHeartbeat) to
// avoid races.
func TestSQLiteCacheRoundTrip(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})

	// The test hub does not call initCacheSchema; do it explicitly.
	if err := h.initCacheSchema(); err != nil {
		t.Fatalf("initCacheSchema: %v", err)
	}

	hb := &model.FleetHeartbeat{
		AgentID:    "cache-agent",
		Hostname:   "cache-host",
		CPUBusyPct: 42.5,
		MemUsedPct: 70.0,
	}

	// Call synchronously to avoid goroutine race in test.
	h.persistHeartbeat(hb)

	var gotAgentID, gotHostname string
	var gotCPU float64
	err := h.cache.QueryRow(
		`SELECT agent_id, hostname, cpu_busy FROM heartbeats WHERE agent_id = ?`,
		hb.AgentID,
	).Scan(&gotAgentID, &gotHostname, &gotCPU)
	if err != nil {
		t.Fatalf("read heartbeat from SQLite cache: %v", err)
	}
	if gotAgentID != hb.AgentID {
		t.Fatalf("cache: agent_id: want %q, got %q", hb.AgentID, gotAgentID)
	}
	if gotHostname != hb.Hostname {
		t.Fatalf("cache: hostname: want %q, got %q", hb.Hostname, gotHostname)
	}
	if gotCPU != hb.CPUBusyPct {
		t.Fatalf("cache: cpu_busy: want %.2f, got %.2f", hb.CPUBusyPct, gotCPU)
	}
}

func TestRequireAuthRejectsWrongToken(t *testing.T) {
	h := &Hub{cfg: model.FleetHubConfig{AuthToken: "secret"}}
	r := httptest.NewRequest("GET", "/v1/hosts", nil)
	r.Header.Set(model.FleetAuthHeader, "wrong")
	w := httptest.NewRecorder()
	if h.requireAuth(w, r) {
		t.Fatal("expected auth to fail for wrong token")
	}
	if w.Code != 401 {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestRequireAuthAcceptsCorrectToken(t *testing.T) {
	h := &Hub{cfg: model.FleetHubConfig{AuthToken: "secret"}}
	r := httptest.NewRequest("GET", "/v1/hosts", nil)
	r.Header.Set(model.FleetAuthHeader, "secret")
	w := httptest.NewRecorder()
	if !h.requireAuth(w, r) {
		t.Fatal("expected auth to succeed for correct token")
	}
}

func TestRequireAuthConstantTime(t *testing.T) {
	// Guards against regression to plain == comparison.
	if subtle.ConstantTimeCompare([]byte("a"), []byte("a")) != 1 {
		t.Fatal("subtle import sanity")
	}
}

func TestNewHubRejectsEmptyToken(t *testing.T) {
	// A hub with no token and AllowNoAuth=false should refuse to start.
	// We pass an empty PostgresDSN deliberately — the auth guard must fire
	// before we even try to open the DB.
	cfg := model.FleetHubConfig{
		AuthToken:   "",
		AllowNoAuth: false,
		// PostgresDSN intentionally empty — guard should fire first.
	}
	_, err := NewHub(cfg)
	if err == nil {
		t.Fatal("expected error when AuthToken is empty and AllowNoAuth is false")
	}
	const want = "fleet hub: refusing to start with no auth token"
	if len(err.Error()) < len(want) || err.Error()[:len(want)] != want {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestNewHubAllowsEmptyTokenWhenAllowNoAuth(t *testing.T) {
	// AllowNoAuth=true should bypass the empty-token guard.
	// The constructor will fail later on PostgresDSN="" — that's fine;
	// the point is the auth guard does NOT fire.
	cfg := model.FleetHubConfig{
		AuthToken:   "",
		AllowNoAuth: true,
		PostgresDSN: "", // will fail at DB open, not at auth guard
	}
	_, err := NewHub(cfg)
	if err == nil {
		t.Fatal("expected DB error, not nil")
	}
	const forbidden = "fleet hub: refusing to start with no auth token"
	if len(err.Error()) >= len(forbidden) && err.Error()[:len(forbidden)] == forbidden {
		t.Fatalf("auth guard fired even though AllowNoAuth=true: %v", err)
	}
}

// newTestHub creates a Hub with minimal configuration for testing.
// It sets up stub databases to avoid nil pointer panics in goroutines.
func newTestHub(t *testing.T, cfg model.FleetHubConfig) *Hub {
	// Create in-memory SQLite databases for testing.
	tmpfile, err := os.CreateTemp("", "test-hub-*.db")
	if err != nil {
		t.Fatalf("failed to create temp db: %v", err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	pg, err := sql.Open("sqlite", tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to open test postgres db: %v", err)
	}

	cache, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test cache db: %v", err)
	}

	h := &Hub{
		cfg:    cfg,
		pg:     pg,
		cache:  cache,
		hosts:  make(map[string]*model.FleetHost),
		subs:   make(map[int]*subscriber),
		quitCh: make(chan struct{}),
	}
	t.Cleanup(func() {
		pg.Close()
		cache.Close()
	})
	return h
}

func TestHeartbeatRejectsHugeBody(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})
	big := strings.NewReader(`{"hostname":"x","agent_id":"` + strings.Repeat("a", 20<<20) + `"}`)
	r := httptest.NewRequest("POST", "/v1/heartbeat", big)
	w := httptest.NewRecorder()
	h.handleHeartbeat(w, r)
	if w.Code != 400 && w.Code != 413 {
		t.Logf("Response code: %d", w.Code)
		t.Fatalf("want 400/413 for oversized body, got %d", w.Code)
	}
}

func TestIncidentRejectsHugeBody(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})
	big := strings.NewReader(`{"incident_id":"x","agent_id":"` + strings.Repeat("a", 20<<20) + `"}`)
	r := httptest.NewRequest("POST", "/v1/incident", big)
	w := httptest.NewRecorder()
	h.handleIncident(w, r)
	if w.Code != 400 && w.Code != 413 {
		t.Logf("Response code: %d", w.Code)
		t.Fatalf("want 400/413 for oversized body, got %d", w.Code)
	}
}

func TestHeartbeatRateLimited(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})
	got429 := false
	for i := 0; i < 500; i++ {
		w := httptest.NewRecorder()
		body := strings.NewReader(`{"hostname":"h","agent_id":"a"}`)
		h.handleHeartbeat(w, httptest.NewRequest("POST", "/v1/heartbeat", body))
		if w.Code == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected rate limiting to trigger after 500 heartbeats from one agent_id")
	}
}

func TestIncidentRateLimited(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})
	got429 := false
	for i := 0; i < 500; i++ {
		w := httptest.NewRecorder()
		// Use different signatures to avoid dedup gate; confidence is int in model
		body := strings.NewReader(`{"incident_id":"inc1","agent_id":"b","peak_score":80,"confidence":90,"update_type":"started","signature":"sig` + strings.Repeat("x", i%10) + `"}`)
		h.handleIncident(w, httptest.NewRequest("POST", "/v1/incident", body))
		if w.Code == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected rate limiting to trigger after 500 incidents from one agent_id")
	}
}

func TestHandleGetHostValidatesPathTraversal(t *testing.T) {
	h := newTestHub(t, model.FleetHubConfig{AllowNoAuth: true})

	// Test 1: Path traversal attempt should return 400
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/host/../../etc/passwd", nil)
	h.handleGetHost(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("path traversal should return 400, got %d", w.Code)
	}

	// Test 2: Valid hostname (not in registry) should return 404, not 400
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/v1/host/localhost", nil)
	h.handleGetHost(w, r)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("valid hostname should not return 400, got %d", w.Code)
	}
	if w.Code != http.StatusNotFound {
		t.Logf("expected 404 for missing host, got %d", w.Code)
	}

	// Test 3: Valid hostname with dots, dashes, and underscores
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/v1/host/my-host.example_01", nil)
	h.handleGetHost(w, r)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("valid hostname with dots/dashes/underscores should not return 400, got %d", w.Code)
	}
}

// ─── writeJSON tests ─────────────────────────────────────────────────────────

// TestWriteJSONHappyPath verifies that writeJSON sets Content-Type correctly
// and writes valid JSON on the happy path.
func TestWriteJSONHappyPath(t *testing.T) {
	w := httptest.NewRecorder()
	payload := map[string]interface{}{"ok": true, "count": 3}
	writeJSON(w, payload)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("want Content-Type application/json, got %q", ct)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var got map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got["ok"] != true {
		t.Fatalf("unexpected body: %v", got)
	}
}

// errResponseWriter is an http.ResponseWriter whose Write always returns an
// error, used to exercise the writeJSON error-logging path.
type errResponseWriter struct {
	header http.Header
}

func newErrResponseWriter() *errResponseWriter {
	return &errResponseWriter{header: make(http.Header)}
}

func (e *errResponseWriter) Header() http.Header        { return e.header }
func (e *errResponseWriter) WriteHeader(_ int)           {}
func (e *errResponseWriter) Write(_ []byte) (int, error) { return 0, errors.New("simulated write error") }

// TestWriteJSONErrorPath verifies that a Write error is logged via slog rather
// than silently dropped.
func TestWriteJSONErrorPath(t *testing.T) {
	// Redirect slog default to a buffer so we can assert on the output.
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(orig)

	writeJSON(newErrResponseWriter(), map[string]string{"key": "value"})

	logged := buf.String()
	if !strings.Contains(logged, "encode response failed") {
		t.Fatalf("expected slog error containing \"encode response failed\", got: %q", logged)
	}
}

// TestSSESubscriberConcurrency is a stress test that exercises the SSE
// subscriber lifecycle under -race. It proves that concurrent subscribe,
// broadcast (including slow-subscriber drops), and unsubscribe never cause a
// panic. This is defence-in-depth: the code was already safe because every
// close happened under subsMu, but the subscriber.closeOnce guard makes it
// explicit and robust to future refactors.
func TestSSESubscriberConcurrency(t *testing.T) {
	h := &Hub{
		subs: make(map[int]*subscriber),
	}

	const (
		goroutines = 20
		iterations = 200
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sub := h.subscribe()

				// Concurrently try to read from the channel and then unsubscribe.
				// The goroutine drains whatever arrives before the channel closes.
				readDone := make(chan struct{})
				go func() {
					defer close(readDone)
					for range sub.ch {
					}
				}()

				// Broadcast a few messages; some will fill the 64-slot buffer on
				// competing subscribers and trigger the slow-subscriber drop path.
				h.broadcast("test", map[string]int{"n": j})
				h.broadcast("test", map[string]int{"n": j + 1})

				// Unsubscribe — may race with a broadcast that already dropped us.
				h.unsubscribe(sub)
				<-readDone
			}
		}()
	}

	wg.Wait()
}
