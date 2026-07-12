//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestIsVerifiedTier pins the policy behind readiness-review Finding #4 (verifier
// is additive + label unverified): only Tier A/B count as verified; Tier C
// (probable) and D (inconclusive/abstain) must be labeled unverified.
func TestIsVerifiedTier(t *testing.T) {
	verified := []model.VerificationTier{model.TierAConfirmed, model.TierBVerified}
	unverified := []model.VerificationTier{model.TierCProbable, model.TierDInconclusive}

	for _, tr := range verified {
		if !isVerifiedTier(tr) {
			t.Errorf("tier %v should count as verified", tr)
		}
	}
	for _, tr := range unverified {
		if isVerifiedTier(tr) {
			t.Errorf("tier %v must NOT count as verified (label it)", tr)
		}
	}
}
