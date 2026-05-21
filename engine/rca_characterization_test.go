package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// TestRCAInvariants locks down the *structural contract* of AnalyzeRCA's
// output across the NEXTGEN Phase 1 refactor. Byte-for-byte equality
// is not used because Go map-iteration order is randomized — exposing
// a pre-existing non-determinism in AnalyzeRCA that NEXTGEN Phase 2+
// aims to fix.
//
// The invariants here are what callers (TUI, fleet hub, why subcommand)
// actually depend on. Phase 1 must preserve every one of them.
func TestRCAInvariants(t *testing.T) {
	fixtures := buildCharacterizationFixtures()
	for name, fixture := range fixtures {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			result := runCharacterizationCase(fixture)

			if result == nil {
				t.Fatal("invariant violated: AnalyzeRCA returned nil")
			}
			// I1: always emits exactly 4 RCA entries — IO, Memory, CPU, Network.
			if got, want := len(result.RCA), 4; got != want {
				t.Errorf("invariant I1 violated: expected %d RCA entries, got %d", want, got)
			}
			// I2: every standard bottleneck name must appear exactly once.
			want := map[string]bool{
				BottleneckIO: false, BottleneckMemory: false,
				BottleneckCPU: false, BottleneckNetwork: false,
			}
			for _, e := range result.RCA {
				if _, ok := want[e.Bottleneck]; !ok {
					t.Errorf("invariant I2 violated: unknown bottleneck %q", e.Bottleneck)
					continue
				}
				if want[e.Bottleneck] {
					t.Errorf("invariant I2 violated: duplicate bottleneck %q", e.Bottleneck)
				}
				want[e.Bottleneck] = true
			}
			for n, seen := range want {
				if !seen {
					t.Errorf("invariant I2 violated: missing bottleneck %q", n)
				}
			}
			// I3: PrimaryScore is in [0, 100].
			if result.PrimaryScore < 0 || result.PrimaryScore > 100 {
				t.Errorf("invariant I3 violated: PrimaryScore=%d out of [0,100]", result.PrimaryScore)
			}
			// I4: Confidence is in [0, 100].
			if result.Confidence < 0 || result.Confidence > 100 {
				t.Errorf("invariant I4 violated: Confidence=%d out of [0,100]", result.Confidence)
			}
			// I5: Health is one of the defined levels.
			switch result.Health {
			case model.HealthOK, model.HealthInconclusive,
				model.HealthDegraded, model.HealthCritical:
			default:
				t.Errorf("invariant I5 violated: Health=%v is not a defined level", result.Health)
			}
			// I6: when PrimaryScore == 0, Health is OK and Confidence is the
			// well-defined OK-confidence constant.
			if result.PrimaryScore == 0 {
				if result.Health != model.HealthOK {
					t.Errorf("invariant I6 violated: score=0 but Health=%v (want OK)", result.Health)
				}
				if result.Confidence != rcaHealthOKConfidence {
					t.Errorf("invariant I6 violated: score=0 but Confidence=%d (want %d)",
						result.Confidence, rcaHealthOKConfidence)
				}
			}
			// I7: every RCA entry has DomainConf in [0, 1].
			for i, e := range result.RCA {
				if e.DomainConf < 0 || e.DomainConf > 1.0 {
					t.Errorf("invariant I7 violated: RCA[%d].DomainConf=%g out of [0,1]", i, e.DomainConf)
				}
			}
			// I8: every Evidence's Confidence is in [0, 1].
			for i, e := range result.RCA {
				for j, ev := range e.EvidenceV2 {
					if ev.Confidence < 0 || ev.Confidence > 1.0 {
						t.Errorf("invariant I8 violated: RCA[%d].EvidenceV2[%d].Confidence=%g out of [0,1]",
							i, j, ev.Confidence)
					}
				}
			}
			// I9: USEChecks has exactly 4 resources (CPU, Memory, Disk, Network).
			if got, want := len(result.USEChecks), 4; got != want {
				t.Errorf("invariant I9 violated: USEChecks length %d, want %d", got, want)
			}
			// I10 (NEXTGEN Phase 2): every Fact emitted is well-formed.
			// CPU domain is the first migrated; future commits extend
			// this assertion to memory/io/network as they migrate.
			for i, f := range result.Facts {
				if !f.IsValid() {
					t.Errorf("invariant I10 violated: Facts[%d]=%+v failed IsValid()", i, f)
				}
				if f.Confidence < 0 || f.Confidence > 1.0 {
					t.Errorf("invariant I10 violated: Facts[%d].Confidence=%v out of [0,1]",
						i, f.Confidence)
				}
			}
			// I11: each of the 4 standard domains emits at least one
			// Fact. Per-domain minimums codify the Phase 2 migration:
			//   CPU     >= 6  (psi, busy, runqueue, ctxswitch, steal, throttle)
			//   Memory  >= 7  (psi, available, reclaim, swap_in, swap_out, faults, oom)
			//   IO      >= 6  (psi, dstate, latency, util, queue, writeback)
			//   Network >= 4  (drops, retrans, conntrack, softirq)
			// If a future commit removes one, update both the analyzer
			// and the corresponding bound here in the same commit.
			byDomain := map[model.Domain]int{}
			for _, f := range result.Facts {
				byDomain[f.Domain]++
			}
			for _, c := range []struct {
				dom model.Domain
				min int
			}{
				{model.DomainCPU, 6},
				{model.DomainMemory, 7},
				{model.DomainIO, 6},
				{model.DomainNetwork, 4},
			} {
				if got := byDomain[c.dom]; got < c.min {
					t.Errorf("invariant I11 violated: domain %q emitted %d facts, want >= %d",
						c.dom, got, c.min)
				}
			}
		})
	}
}

// TestRCADeterminismDiagnostic is a NON-FAILING test that REPORTS
// whether AnalyzeRCA is deterministic. Determinism is a NEXTGEN
// Phase 2+ goal — we record the current state here so progress is
// measurable.
//
// Failure mode: t.Log only, never t.Errorf. The test is informational.
func TestRCADeterminismDiagnostic(t *testing.T) {
	fixtures := buildCharacterizationFixtures()
	for name, fixture := range fixtures {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			r1 := runCharacterizationCase(fixture)
			r2 := runCharacterizationCase(fixture)
			// Compare only the headline summary fields — full struct
			// comparison would fail constantly due to map order.
			if r1.Health != r2.Health {
				t.Logf("non-deterministic: Health %v vs %v", r1.Health, r2.Health)
			}
			if r1.PrimaryScore != r2.PrimaryScore {
				t.Logf("non-deterministic: PrimaryScore %d vs %d", r1.PrimaryScore, r2.PrimaryScore)
			}
			if r1.Confidence != r2.Confidence {
				t.Logf("non-deterministic: Confidence %d vs %d", r1.Confidence, r2.Confidence)
			}
			if r1.PrimaryBottleneck != r2.PrimaryBottleneck {
				t.Logf("non-deterministic: PrimaryBottleneck %q vs %q", r1.PrimaryBottleneck, r2.PrimaryBottleneck)
			}
			if len(r1.RCA) != len(r2.RCA) {
				t.Logf("non-deterministic: RCA length %d vs %d", len(r1.RCA), len(r2.RCA))
			}
		})
	}
}

type characterizationCase struct {
	prev *model.Snapshot
	curr *model.Snapshot
}

func runCharacterizationCase(c characterizationCase) *model.AnalysisResult {
	rates := ComputeRates(c.prev, c.curr)
	hist := NewHistory(60, 1)
	return AnalyzeRCA(c.curr, &rates, hist, nil, nil)
}

func buildCharacterizationFixtures() map[string]characterizationCase {
	base := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	mkBase := func() *model.Snapshot {
		return &model.Snapshot{HostID: "char-test", Timestamp: base}
	}
	// Every realistic host has memory; the memory analyzer early-
	// returns when Total==0 and consumers (Phase 2 Fact emission)
	// would see no memory facts. Set a baseline 16 GiB across all
	// fixtures so memory data is always present.
	withMem := func(s *model.Snapshot) *model.Snapshot {
		s.Global.Memory.Total = 16 * 1024 * 1024 * 1024
		s.Global.Memory.Available = 12 * 1024 * 1024 * 1024
		return s
	}

	idleCurr := withMem(mkBase())
	idleCurr.Timestamp = base.Add(time.Second)
	idleCurr.Global.CPU.NumCPUs = 4
	idleCurr.Global.CPU.LoadAvg.Load1 = 0.1

	loadedCurr := withMem(mkBase())
	loadedCurr.Timestamp = base.Add(time.Second)
	loadedCurr.Global.CPU.NumCPUs = 4
	loadedCurr.Global.CPU.LoadAvg.Load1 = 8.0
	loadedCurr.Global.Memory.Available = 1 * 1024 * 1024 * 1024 // override: stressed

	withProc := withMem(mkBase())
	withProc.Timestamp = base.Add(time.Second)
	withProc.Global.CPU.NumCPUs = 2
	withProc.Processes = []model.ProcessMetrics{{PID: 1234, Comm: "synthproc"}}

	return map[string]characterizationCase{
		"01-idle":      {prev: mkBase(), curr: idleCurr},
		"02-loaded":    {prev: mkBase(), curr: loadedCurr},
		"03-with-proc": {prev: mkBase(), curr: withProc},
	}
}
