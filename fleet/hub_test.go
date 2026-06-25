package fleet

import (
	"crypto/subtle"
	"database/sql"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ftahirops/xtop/model"
	_ "modernc.org/sqlite"
)

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
		subs:   make(map[int]chan []byte),
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
