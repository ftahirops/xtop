package engine

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// stubClient returns a minimal FleetClient that satisfies Observe's
// dependencies without actually opening an HTTP connection. memQueue is
// inspected directly to count emissions.
func stubClient(quality FleetQuality) *FleetClient {
	return &FleetClient{
		quality: quality,
		agentID: "test-agent",
		maxQueue: 1024,
	}
}

// degradedResult builds an AnalysisResult with the given signal quality.
// Signature derives from RCA evidence IDs so score/conf changes don't
// accidentally flip the signature.
func degradedResult(score, conf int, bottleneck, evidenceID string) *model.AnalysisResult {
	return &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: bottleneck,
		PrimaryScore:      score,
		Confidence:        conf,
		RCA: []model.RCAEntry{{
			Bottleneck: bottleneck,
			EvidenceV2: []model.Evidence{{ID: evidenceID, Strength: 0.8}},
		}},
	}
}

func mkSnap() *model.Snapshot {
	return &model.Snapshot{}
}

// countEmits returns how many INCIDENT payloads are queued (heartbeats
// go through the same memQueue but on a different endpoint; we only care
// about incident emissions when measuring the quality gate).
func countEmits(fc *FleetClient) int {
	n := 0
	for _, m := range fc.memQueue {
		if m.Endpoint == model.FleetEndpointIncident {
			n++
		}
	}
	return n
}

// incidentMessages returns only the incident-endpoint messages in queue
// order — tests that inspect payload details (e.g. UpdateType) use this
// instead of indexing memQueue directly.
func incidentMessages(fc *FleetClient) []queuedMsg {
	var out []queuedMsg
	for _, m := range fc.memQueue {
		if m.Endpoint == model.FleetEndpointIncident {
			out = append(out, m)
		}
	}
	return out
}

func TestQualityGate_ZeroScoreZeroConfNeverEmits(t *testing.T) {
	fc := stubClient(defaultFleetQuality())
	for i := 0; i < 20; i++ {
		fc.Observe(mkSnap(), degradedResult(0, 0, "cpu", "runqlat"),
			"host-a", "v0.43.0")
	}
	if n := countEmits(fc); n != 0 {
		t.Errorf("emitted %d payloads for pure-zero incident stream; want 0", n)
	}
}

func TestQualityGate_BelowThresholdNeverEmits(t *testing.T) {
	fc := stubClient(defaultFleetQuality())
	// score=20 below default 30; conf=50 okay — still sub-threshold
	// because both must exceed.
	for i := 0; i < 10; i++ {
		fc.Observe(mkSnap(), degradedResult(20, 50, "cpu", "runqlat"),
			"host-a", "v0.43.0")
	}
	if n := countEmits(fc); n != 0 {
		t.Errorf("emitted %d for below-bar stream; want 0", n)
	}
	// Resolved arrives — still no emission (we never announced a start).
	fc.Observe(mkSnap(), &model.AnalysisResult{Health: model.HealthOK}, "host-a", "v0.43.0")
	if n := countEmits(fc); n != 0 {
		t.Errorf("stray Resolved emitted after never-announced incident; got %d", n)
	}
}

func TestQualityGate_EmitsOnlyAfterSustainedBar(t *testing.T) {
	fc := stubClient(defaultFleetQuality())
	good := degradedResult(60, 80, "cpu", "runqlat")

	// First 2 good ticks → no emission yet (default MinStartTicks = 3).
	fc.Observe(mkSnap(), good, "host-a", "v0.43.0")
	fc.Observe(mkSnap(), good, "host-a", "v0.43.0")
	if n := countEmits(fc); n != 0 {
		t.Errorf("emitted %d after 2 ticks; default threshold is 3", n)
	}
	// Third tick → Started.
	fc.Observe(mkSnap(), good, "host-a", "v0.43.0")
	if n := countEmits(fc); n != 1 {
		t.Errorf("expected 1 Started emission after 3 sustained ticks, got %d", n)
	}
	// Further same-signature ticks at same score → no new emission.
	fc.Observe(mkSnap(), good, "host-a", "v0.43.0")
	fc.Observe(mkSnap(), good, "host-a", "v0.43.0")
	if n := countEmits(fc); n != 1 {
		t.Errorf("follow-up ticks should not emit: got %d", n)
	}
}

func TestQualityGate_EmitsResolvedOnlyWhenStartWasEmitted(t *testing.T) {
	fc := stubClient(defaultFleetQuality())
	good := degradedResult(60, 80, "cpu", "runqlat")

	// Get to Started.
	for i := 0; i < 3; i++ {
		fc.Observe(mkSnap(), good, "host-a", "v0.43.0")
	}
	if countEmits(fc) != 1 {
		t.Fatalf("precondition: expected 1 Started")
	}
	// Health returns to OK → Resolved emits.
	fc.Observe(mkSnap(), &model.AnalysisResult{Health: model.HealthOK}, "host-a", "v0.43.0")
	if countEmits(fc) != 2 {
		t.Errorf("expected Started+Resolved (2 emissions), got %d", countEmits(fc))
	}
	// Check the second emission type.
	msgs := incidentMessages(fc)
	if len(msgs) < 2 {
		t.Fatalf("want 2 incident messages, got %d", len(msgs))
	}
	var payload model.FleetIncident
	if err := unmarshal(t, msgs[1].Body, &payload); err == nil {
		if payload.UpdateType != model.IncidentResolved {
			t.Errorf("second emission = %q, want Resolved", payload.UpdateType)
		}
	}
}

func TestQualityGate_EscalationRateLimit(t *testing.T) {
	fc := stubClient(defaultFleetQuality())

	// Establish an initial Started incident (cpu).
	good := degradedResult(60, 80, "cpu", "runqlat")
	for i := 0; i < 3; i++ {
		fc.Observe(mkSnap(), good, "host-a", "v0.43.0")
	}
	baseEmits := countEmits(fc)
	if baseEmits != 1 {
		t.Fatalf("precondition: 1 Started, got %d", baseEmits)
	}

	// Immediate flip to a different signature — should NOT escalate yet
	// (MinEscalationGap hasn't passed).
	flipped := degradedResult(60, 80, "memory", "swap_churn")
	for i := 0; i < 3; i++ {
		fc.Observe(mkSnap(), flipped, "host-a", "v0.43.0")
	}
	if countEmits(fc) != baseEmits {
		t.Errorf("signature flip within gap emitted %d extra events; want 0",
			countEmits(fc)-baseEmits)
	}

	// Force the gap to expire.
	fc.lastEscalationAt = time.Now().Add(-1 * time.Minute)
	fc.Observe(mkSnap(), flipped, "host-a", "v0.43.0")
	// After the gap, the first above-bar tick opens a new incident →
	// Resolved(escalated) + Started = +2 emissions.
	if got := countEmits(fc) - baseEmits; got != 2 {
		t.Errorf("post-gap escalation produced %d emissions (want Resolved+Started=2)", got)
	}
}

func TestQualityGate_OneOffSpikeProducesNothing(t *testing.T) {
	fc := stubClient(defaultFleetQuality())
	// Single bar-passing tick followed by recovery — the classic "normal
	// spike" that was flooding the hub. Must produce zero emissions.
	fc.Observe(mkSnap(), degradedResult(80, 90, "cpu", "runqlat"), "host-a", "v0.43.0")
	fc.Observe(mkSnap(), &model.AnalysisResult{Health: model.HealthOK}, "host-a", "v0.43.0")
	if n := countEmits(fc); n != 0 {
		t.Errorf("one-off spike emitted %d events; want 0", n)
	}
}

func TestQualityGate_EnvOverrides(t *testing.T) {
	t.Setenv("XTOP_FLEET_QUALITY_MIN_SCORE", "50")
	t.Setenv("XTOP_FLEET_QUALITY_MIN_CONF", "75")
	t.Setenv("XTOP_FLEET_QUALITY_MIN_TICKS", "5")
	t.Setenv("XTOP_FLEET_QUALITY_ESC_GAP_SEC", "60")
	q := defaultFleetQuality()
	if q.MinPeakScore != 50 || q.MinConfidence != 75 || q.MinStartTicks != 5 || q.MinEscalationGap != 60*time.Second {
		t.Errorf("env override failed: %+v", q)
	}
}

// unmarshal helper keeps the test readable — the fleet client serializes
// payloads as JSON before enqueueing, so tests need to round-trip.
func unmarshal(t *testing.T, body []byte, out interface{}) error {
	t.Helper()
	return json.Unmarshal(body, out)
}
