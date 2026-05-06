package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// TestSnapshotRecentChanges_CapsAt20: defensive copy + 20-entry cap.
func TestSnapshotRecentChanges_CapsAt20(t *testing.T) {
	res := &model.AnalysisResult{}
	for i := 0; i < 30; i++ {
		res.Changes = append(res.Changes, model.SystemChange{
			Type: "package_install", Detail: "pkg", When: time.Now(),
		})
	}
	got := snapshotRecentChanges(res)
	if len(got) != 20 {
		t.Errorf("len = %d, want 20", len(got))
	}
}

// TestLifecycle_ChangesStampedAtConfirm: when promotion to Confirmed fires,
// result.Changes is captured into r.active.ChangesAtConfirm.
func TestLifecycle_ChangesStampedAtConfirm(t *testing.T) {
	r := newTestRecorder(t)

	change := model.SystemChange{
		Type: "package_install", Detail: "openssl 3.0.10", When: time.Now(),
	}
	resWithChange := makeResult(BottleneckIO, 60, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", minSustainedSec+1),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", minSustainedSec+1),
	})
	resWithChange.Changes = []model.SystemChange{change}

	got := r.Record(resWithChange)
	if got == nil || got.State != IncidentConfirmed {
		t.Fatalf("expected immediate promotion to Confirmed (sustained=7s on first tick), got %+v", got)
	}
	if len(got.ChangesAtConfirm) != 1 || got.ChangesAtConfirm[0].Detail != "openssl 3.0.10" {
		t.Errorf("ChangesAtConfirm not captured, got %+v", got.ChangesAtConfirm)
	}
}

// TestLifecycle_FleetPeersStamped: cross-host correlation string is captured.
func TestLifecycle_FleetPeersStamped(t *testing.T) {
	r := newTestRecorder(t)

	res := makeResult(BottleneckIO, 60, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", minSustainedSec+1),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", minSustainedSec+1),
	})
	res.CrossHostCorrelation = "Host db1 also reports IO Starvation (score 78)"

	got := r.Record(res)
	if got == nil || got.State != IncidentConfirmed {
		t.Fatalf("expected promotion, got %+v", got)
	}
	if got.FleetPeersAtConfirm != "Host db1 also reports IO Starvation (score 78)" {
		t.Errorf("FleetPeersAtConfirm = %q", got.FleetPeersAtConfirm)
	}
}
