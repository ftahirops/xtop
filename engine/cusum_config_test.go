package engine

import (
	"testing"
)

func TestCUSUMTuning_PerDistribution(t *testing.T) {
	// Default: right-skewed should tolerate larger deviations than normal —
	// otherwise packet-drop spikes constantly fire change-points.
	if cusumRightSkewed.HMul <= cusumNormal.HMul {
		t.Errorf("right-skewed HMul (%v) should exceed normal HMul (%v)",
			cusumRightSkewed.HMul, cusumNormal.HMul)
	}
	// Bimodal sits between normal and skewed.
	if !(cusumBimodal.HMul >= cusumNormal.HMul && cusumBimodal.HMul <= cusumRightSkewed.HMul) {
		t.Errorf("bimodal HMul should sit between normal and skewed: %v", cusumBimodal.HMul)
	}
}

func TestCUSUMFor_SelectsByMetricClassification(t *testing.T) {
	// DistRightSkewed via metric ID → skewed tuning.
	cs := newCusumStateForMetric("tcp_retrans", 10, 2)
	want := cusumRightSkewed.HMul * 2
	if cs.H != want {
		t.Errorf("retrans H = %v, want %v (skewed HMul * sigma)", cs.H, want)
	}
	// Normal metric → normal tuning.
	cs = newCusumStateForMetric("cpu_busy_pct", 40, 5)
	if cs.H != cusumNormal.HMul*5 {
		t.Errorf("cpu H = %v, want %v", cs.H, cusumNormal.HMul*5)
	}
}

func TestCUSUMState_DetectsShift(t *testing.T) {
	// Feed a state tuned for a normal-ish metric with large H so random walk
	// doesn't trip it, then push a clean mean-shift.
	cs := newCusumStateTuned(100, 5, CUSUMTuning{KMul: 0.5, HMul: 4})
	// Stable samples around the mean — must NOT trigger.
	for _, v := range []float64{98, 101, 99, 102, 100, 103, 97} {
		if cs.Update(v) {
			t.Fatalf("stable sample %v triggered a false change-point", v)
		}
	}
	// A sustained shift to mean+3σ should trigger within a few samples.
	triggered := false
	for i := 0; i < 20; i++ {
		if cs.Update(115) {
			triggered = true
			break
		}
	}
	if !triggered {
		t.Errorf("CUSUM should have detected a sustained +3σ shift within 20 samples")
	}
}
