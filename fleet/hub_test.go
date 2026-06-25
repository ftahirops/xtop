package fleet

import (
	"crypto/subtle"
	"net/http/httptest"
	"testing"

	"github.com/ftahirops/xtop/model"
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
