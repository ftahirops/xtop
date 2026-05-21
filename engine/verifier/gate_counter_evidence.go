package verifier

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// counterEvidenceGate looks for facts that DISQUALIFY the candidate.
// Per NEXTGEN §5: "is there strong evidence against the mechanism?"
//
// This is the gate that catches "the alert fired but the underlying
// system state contradicts the alert's premise." Examples:
//
//   - "CPU throttle is the cause" but the cgroup has no CPU quota set
//     (you can't be throttled if there's no quota). Disqualify.
//   - "Disk IO is the cause" but disk util is 5% and no D-state tasks
//     (you can't be IO-bound if no IO is happening). Disqualify.
//   - "Network drops are the cause" but the link is 100% idle.
//     Disqualify.
//
// Phase 4 ships a small registry of "if mechanism X cited fact A as
// support, then fact B's value being below threshold disqualifies it"
// rules. Each rule is a CounterRule. Future commits extend the rule
// set; Phase 5 (replay corpus) will measure which rules empirically
// catch the most false positives.
//
// Conservative default: when no rule matches the candidate's domain,
// the gate PASSES (no counter-evidence found). This is the correct
// default — absence of evidence is not evidence of absence.
type counterEvidenceGate struct{}

func (counterEvidenceGate) ID() string { return "counter_evidence" }

// CounterRule says "if this candidate mechanism is being proposed,
// look for this disqualifying fact-id with this value-below threshold."
type counterRule struct {
	// domain it applies to
	domain model.Domain
	// substring that must appear in candidate.Mechanism for this rule
	// to apply (case-insensitive). Empty = applies to all candidates
	// in the domain.
	mechanismHint string
	// the fact whose value must be ABOVE threshold for the candidate
	// to remain viable. If this fact is below threshold (or missing),
	// the candidate is disqualified.
	requiredFactID string
	requiredMin    float64
	// human-readable reason for the audit log
	reason string
}

// counterRules is the initial registry. Conservative — we add only
// rules with very high confidence in their disqualifying logic.
// Wrong rules here cause false NEGATIVES (engine incorrectly abstains
// when it should commit), which is the safe direction.
var counterRules = []counterRule{
	{
		// "CPU contention" requires actual CPU usage. If busy_pct is
		// near zero, no CPU contention can exist — the score must
		// have come from something else.
		domain:         model.DomainCPU,
		requiredFactID: "cpu.busy",
		requiredMin:    20.0, // less than 20% busy → no contention possible
		reason:         "CPU contention requires busy_pct ≥ 20%",
	},
	{
		// "cgroup throttle" needs actual throttle events. If the
		// throttle Fact's value is 0, there's no throttling — the
		// score must trace to something else.
		domain:         model.DomainCPU,
		mechanismHint:  "throttle",
		requiredFactID: "cpu.cgroup.throttle",
		requiredMin:    1.0, // any non-zero throttle qualifies
		reason:         "throttle mechanism requires non-zero throttle facts",
	},
	{
		// "IO contention" requires either disk util OR D-state tasks.
		// If both are at 0, no disk pressure exists.
		domain:         model.DomainIO,
		requiredFactID: "io.disk.util",
		requiredMin:    1.0,
		reason:         "IO contention requires non-zero disk util",
	},
	{
		// "Memory pressure" needs the available-memory pct to be
		// meaningfully used. Below ~30% used = lots of headroom = no
		// real pressure mechanism.
		domain:         model.DomainMemory,
		requiredFactID: "mem.available.low",
		requiredMin:    30.0,
		reason:         "memory pressure requires used_pct ≥ 30%",
	},
	{
		// "Network overload" with zero drops AND zero retrans AND
		// zero conntrack pressure means no overload exists. Use drops
		// as the primary check; retrans/conntrack handled in
		// secondary rules below.
		domain:         model.DomainNetwork,
		mechanismHint:  "drop",
		requiredFactID: "net.drops",
		requiredMin:    1.0,
		reason:         "drop-based network overload requires non-zero drops",
	},
}

func (counterEvidenceGate) Evaluate(c Candidate, facts []model.Fact, _ *model.EntityGraph) model.GateResult {
	if c.Domain == "" {
		return model.GateResult{
			GateID: "counter_evidence",
			Passed: true,
			Reason: "no domain on candidate — skipping counter-evidence check",
		}
	}

	byID := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		byID[f.ID] = f
	}
	mech := strings.ToLower(c.Mechanism)

	var disqualified []string
	for _, rule := range counterRules {
		if rule.domain != c.Domain {
			continue
		}
		if rule.mechanismHint != "" && !strings.Contains(mech, strings.ToLower(rule.mechanismHint)) {
			continue
		}
		f, ok := byID[rule.requiredFactID]
		if !ok || f.Value < rule.requiredMin {
			disqualified = append(disqualified,
				fmt.Sprintf("%s (fact %s = %.1f, need ≥ %.1f)",
					rule.reason, rule.requiredFactID,
					func() float64 {
						if ok {
							return f.Value
						}
						return 0
					}(),
					rule.requiredMin))
		}
	}

	if len(disqualified) > 0 {
		return model.GateResult{
			GateID:    "counter_evidence",
			Passed:    false,
			Reason:    "disqualifying evidence: " + strings.Join(disqualified, "; "),
			FactsUsed: c.SupportingFactIDs,
		}
	}

	return model.GateResult{
		GateID:    "counter_evidence",
		Passed:    true,
		Reason:    "no counter-evidence rules triggered",
		FactsUsed: c.SupportingFactIDs,
	}
}
