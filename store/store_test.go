package store

// SQLite round-trip tests. Uses an in-memory database (:memory:) so no
// filesystem or root access is required.

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// openTestStore opens an in-memory SQLite store and runs Migrate.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestOpenAndMigrate asserts that Open + Migrate succeed on a fresh DB.
func TestOpenAndMigrate(t *testing.T) {
	s := openTestStore(t) // error-fails inside if anything goes wrong
	_ = s
}

// TestInsertAndGetIncident asserts a complete insert→get round-trip for an
// incident: every field written must survive the scan unchanged.
func TestInsertAndGetIncident(t *testing.T) {
	s := openTestStore(t)

	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	ev := model.Event{
		ID:             "test-incident-001",
		StartTime:      now,
		PeakHealth:     model.HealthCritical,
		Bottleneck:     "cpu",
		PeakScore:      87,
		CulpritProcess: "mongod",
		CulpritPID:     1234,
		CulpritCgroup:  "cgroup:/system.slice/mongod.service",
		CausalChain:    "CPU contention → latency",
		Evidence:       []string{"cpu.psi.avg10=65", "cpu.busy=85"},
		PeakCPUBusy:    85.0,
		PeakMemUsedPct: 42.0,
		PeakIOPSI:      3.2,
	}

	if err := s.InsertIncident(ev, "fp-cpu-mongod", nil); err != nil {
		t.Fatalf("InsertIncident: %v", err)
	}

	got, err := s.GetIncident("test-incident-001")
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}

	if got.ID != ev.ID {
		t.Errorf("ID: %q vs %q", got.ID, ev.ID)
	}
	if got.Fingerprint != "fp-cpu-mongod" {
		t.Errorf("Fingerprint: %q", got.Fingerprint)
	}
	if got.Bottleneck != ev.Bottleneck {
		t.Errorf("Bottleneck: %q vs %q", got.Bottleneck, ev.Bottleneck)
	}
	if got.PeakScore != ev.PeakScore {
		t.Errorf("PeakScore: %d vs %d", got.PeakScore, ev.PeakScore)
	}
	if got.CulpritProcess != ev.CulpritProcess {
		t.Errorf("CulpritProcess: %q vs %q", got.CulpritProcess, ev.CulpritProcess)
	}
	if got.CulpritPID != ev.CulpritPID {
		t.Errorf("CulpritPID: %d vs %d", got.CulpritPID, ev.CulpritPID)
	}
	if got.PeakCPU != ev.PeakCPUBusy {
		t.Errorf("PeakCPU: %f vs %f", got.PeakCPU, ev.PeakCPUBusy)
	}
	if got.PeakMem != ev.PeakMemUsedPct {
		t.Errorf("PeakMem: %f vs %f", got.PeakMem, ev.PeakMemUsedPct)
	}
}

// TestGetIncident_NotFound asserts that GetIncident returns an error for a
// missing ID (not a panic or silent zero-value return).
func TestGetIncident_NotFound(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetIncident("nonexistent")
	if err == nil {
		t.Error("expected error for missing incident; got nil")
	}
}

// TestInsertAndGetOffenders asserts offender rows survive a round-trip.
func TestInsertAndGetOffenders(t *testing.T) {
	s := openTestStore(t)

	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	ev := model.Event{
		ID:         "test-incident-002",
		StartTime:  now,
		PeakHealth: model.HealthDegraded,
		Bottleneck: "io",
		PeakScore:  55,
	}
	offenders := []model.ImpactScore{
		{PID: 999, Comm: "mysqld", Service: "mysql", Composite: 75.5,
			CPUSaturation: 0.6, RSS: 512 * 1024 * 1024, WriteMBs: 12.3},
	}
	if err := s.InsertIncident(ev, "fp-io-mysql", offenders); err != nil {
		t.Fatalf("InsertIncident: %v", err)
	}

	got, err := s.GetOffenders("test-incident-002")
	if err != nil {
		t.Fatalf("GetOffenders: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 offender; got %d", len(got))
	}
	o := got[0]
	if o.PID != 999 {
		t.Errorf("PID: %d vs 999", o.PID)
	}
	if o.Comm != "mysqld" {
		t.Errorf("Comm: %q vs mysqld", o.Comm)
	}
	if o.ImpactScore != 75.5 {
		t.Errorf("ImpactScore: %f vs 75.5", o.ImpactScore)
	}
}

// TestListIncidents asserts ListIncidents returns incidents in
// start_time-descending order.
func TestListIncidents(t *testing.T) {
	s := openTestStore(t)

	base := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	for i, suffix := range []string{"a", "b", "c"} {
		ev := model.Event{
			ID:         "inc-" + suffix,
			StartTime:  base.Add(time.Duration(i) * time.Hour),
			PeakHealth: model.HealthDegraded,
			Bottleneck: "cpu",
			PeakScore:  10 * (i + 1),
		}
		if err := s.InsertIncident(ev, "fp", nil); err != nil {
			t.Fatalf("InsertIncident %s: %v", suffix, err)
		}
	}

	list, err := s.ListIncidents(10, 0)
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 incidents; got %d", len(list))
	}
	// Newest first: c (base+2h), b (base+1h), a (base)
	wantOrder := []string{"inc-c", "inc-b", "inc-a"}
	for i, id := range wantOrder {
		if list[i].ID != id {
			t.Errorf("list[%d].ID=%q, want %q", i, list[i].ID, id)
		}
	}
}

// TestUpsertAndGetFingerprint asserts the fingerprint upsert survives a
// round-trip.
func TestUpsertAndGetFingerprint(t *testing.T) {
	s := openTestStore(t)

	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	fp := Fingerprint{
		FP:          "sha256:abcdef",
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
		AvgDuration: 120,
		SymptomType: "cpu_saturation",
		RootClass:   "cgroup_throttle",
		TopOffender: "mongod",
	}
	if err := s.UpsertFingerprint(fp); err != nil {
		t.Fatalf("UpsertFingerprint: %v", err)
	}

	got, err := s.GetFingerprint("sha256:abcdef")
	if err != nil {
		t.Fatalf("GetFingerprint: %v", err)
	}
	if got.FP != fp.FP {
		t.Errorf("FP: %q vs %q", got.FP, fp.FP)
	}
	if got.TopOffender != fp.TopOffender {
		t.Errorf("TopOffender: %q vs %q", got.TopOffender, fp.TopOffender)
	}
	if got.SymptomType != fp.SymptomType {
		t.Errorf("SymptomType: %q vs %q", got.SymptomType, fp.SymptomType)
	}
	if got.AvgDuration != fp.AvgDuration {
		t.Errorf("AvgDuration: %d vs %d", got.AvgDuration, fp.AvgDuration)
	}
}

// TestPrune asserts old incidents are deleted and recent ones are kept.
func TestPrune(t *testing.T) {
	s := openTestStore(t)

	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, ev := range []model.Event{
		{ID: "old-1", StartTime: old, PeakHealth: model.HealthDegraded, Bottleneck: "cpu", PeakScore: 50},
		{ID: "old-2", StartTime: old.Add(time.Hour), PeakHealth: model.HealthDegraded, Bottleneck: "io", PeakScore: 40},
		{ID: "recent-1", StartTime: recent, PeakHealth: model.HealthCritical, Bottleneck: "cpu", PeakScore: 90},
	} {
		if err := s.InsertIncident(ev, "fp", nil); err != nil {
			t.Fatalf("InsertIncident %s: %v", ev.ID, err)
		}
	}

	n, err := s.Prune(cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 pruned; got %d", n)
	}

	list, err := s.ListIncidents(10, 0)
	if err != nil {
		t.Fatalf("ListIncidents after prune: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 remaining; got %d", len(list))
	}
	if list[0].ID != "recent-1" {
		t.Errorf("remaining ID=%q, want recent-1", list[0].ID)
	}
}
