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
	if got.CulpritCgroup != ev.CulpritCgroup {
		t.Errorf("CulpritCgroup: %q vs %q", got.CulpritCgroup, ev.CulpritCgroup)
	}
	if got.CausalChain != ev.CausalChain {
		t.Errorf("CausalChain: %q vs %q", got.CausalChain, ev.CausalChain)
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

// TestSaveAndLoadConfigBaseline asserts that ConfigBaselineRow values round-trip
// correctly through SaveConfigBaseline / LoadConfigBaseline.
func TestSaveAndLoadConfigBaseline(t *testing.T) {
	s := openTestStore(t)

	now := time.Now().Truncate(time.Second) // stored as unix seconds; sub-second lost
	rows := []ConfigBaselineRow{
		{Key: "kernel.pid_max", Value: "4194304", Domain: "kernel", FirstSeen: now, Acked: false},
		{Key: "vm.swappiness", Value: "60", Domain: "vm", FirstSeen: now, Acked: true},
	}

	if err := s.SaveConfigBaseline(rows); err != nil {
		t.Fatalf("SaveConfigBaseline: %v", err)
	}

	got, err := s.LoadConfigBaseline()
	if err != nil {
		t.Fatalf("LoadConfigBaseline: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows; got %d", len(got))
	}

	// Build a map for order-independent comparison.
	byKey := make(map[string]ConfigBaselineRow, len(got))
	for _, r := range got {
		byKey[r.Key] = r
	}

	for _, want := range rows {
		r, ok := byKey[want.Key]
		if !ok {
			t.Errorf("key %q missing from LoadConfigBaseline", want.Key)
			continue
		}
		if r.Value != want.Value {
			t.Errorf("key %q: Value=%q want %q", want.Key, r.Value, want.Value)
		}
		if r.Domain != want.Domain {
			t.Errorf("key %q: Domain=%q want %q", want.Key, r.Domain, want.Domain)
		}
		if r.Acked != want.Acked {
			t.Errorf("key %q: Acked=%v want %v", want.Key, r.Acked, want.Acked)
		}
		diff := r.FirstSeen.Unix() - want.FirstSeen.Unix()
		if diff < -1 || diff > 1 {
			t.Errorf("key %q: FirstSeen=%v want %v (diff %ds)", want.Key, r.FirstSeen, want.FirstSeen, diff)
		}
	}
}

// TestSaveConfigBaselineUpsert asserts that saving the same key twice updates
// the value/domain/acked but preserves first_seen from the first insert.
func TestSaveConfigBaselineUpsert(t *testing.T) {
	s := openTestStore(t)

	t0 := time.Now().Truncate(time.Second).Add(-time.Hour) // clearly in the past
	initial := []ConfigBaselineRow{
		{Key: "net.core.somaxconn", Value: "128", Domain: "net", FirstSeen: t0, Acked: false},
	}
	if err := s.SaveConfigBaseline(initial); err != nil {
		t.Fatalf("SaveConfigBaseline (initial): %v", err)
	}

	updated := []ConfigBaselineRow{
		{Key: "net.core.somaxconn", Value: "4096", Domain: "net", FirstSeen: time.Now().Truncate(time.Second), Acked: true},
	}
	if err := s.SaveConfigBaseline(updated); err != nil {
		t.Fatalf("SaveConfigBaseline (update): %v", err)
	}

	got, err := s.LoadConfigBaseline()
	if err != nil {
		t.Fatalf("LoadConfigBaseline: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row after upsert; got %d", len(got))
	}
	r := got[0]
	if r.Value != "4096" {
		t.Errorf("Value after upsert: %q want 4096", r.Value)
	}
	if !r.Acked {
		t.Errorf("Acked after upsert: want true, got false")
	}
	// first_seen must be preserved from the original insert (t0), not overwritten.
	if r.FirstSeen.Unix() != t0.Unix() {
		t.Errorf("FirstSeen after upsert: %v want %v (should be preserved)", r.FirstSeen, t0)
	}
}

// TestSaveConfigBaselineEmpty asserts that SaveConfigBaseline with an empty
// slice is a no-op (no error, load returns empty).
func TestSaveConfigBaselineEmpty(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveConfigBaseline(nil); err != nil {
		t.Fatalf("SaveConfigBaseline(nil): %v", err)
	}
	got, err := s.LoadConfigBaseline()
	if err != nil {
		t.Fatalf("LoadConfigBaseline after empty save: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows; got %d", len(got))
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
