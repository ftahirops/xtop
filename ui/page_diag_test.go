package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// TestJournalSigLabel verifies the signature→label mapping.
func TestJournalSigLabel(t *testing.T) {
	cases := []struct {
		sig  string
		want string
	}{
		{"crash_restart_loop", "Crash/restart loop"},
		{"oom_killed", "OOM-killed"},
		{"segfault_panic", "Segfault/panic"},
		{"resource_exhaustion", "Resource exhaustion"},
		{"dependency_failure", "Dependency failure"},
		{"config_auth_error", "Config/auth error"},
		{"error_rate_spike", "Error rate spike"},
		{"unknown_sig", "unknown_sig"}, // passthrough
	}
	for _, c := range cases {
		got := journalSigLabel(c.sig)
		if got != c.want {
			t.Errorf("journalSigLabel(%q) = %q, want %q", c.sig, got, c.want)
		}
	}
}

// TestJournalFindingsIndex verifies index building and empty-findings filtering.
func TestJournalFindingsIndex(t *testing.T) {
	logs := model.LogMetrics{
		Services: []model.ServiceLogStats{
			{Name: "mysql", Findings: []model.JournalFinding{
				{Signature: "crash_restart_loop", Severity: model.DiagCrit, Count: 3},
			}},
			{Name: "nginx", Findings: nil}, // no findings — should not appear
		},
	}
	idx := journalFindingsIndex(logs)
	if _, ok := idx["mysql"]; !ok {
		t.Error("expected 'mysql' in index")
	}
	if _, ok := idx["nginx"]; ok {
		t.Error("'nginx' (no findings) should not appear in index")
	}
}

// TestRenderDiagPage_JournalFindings is the primary integration test:
// construct a Snapshot with a service that has JournalFindings and verify
// the rendered output contains the signature label, count, severity badge,
// and truncated sample line.
func TestRenderDiagPage_JournalFindings(t *testing.T) {
	snap := &model.Snapshot{
		Global: model.GlobalMetrics{
			Diagnostics: model.DiagMetrics{
				Services: []model.ServiceDiag{
					{
						Name:      "mysql",
						Available: true,
						WorstSev:  model.DiagCrit,
						Findings:  nil, // no DiagFindings — only journal findings
					},
				},
			},
			Logs: model.LogMetrics{
				Services: []model.ServiceLogStats{
					{
						Name: "mysql",
						Findings: []model.JournalFinding{
							{
								Signature: "crash_restart_loop",
								Severity:  model.DiagCrit,
								Count:     5,
								Sample:    "main process exited, code=killed, status=9/KILL",
								FirstSeen: time.Now().Add(-10 * time.Minute),
								LastSeen:  time.Now(),
							},
							{
								Signature: "oom_killed",
								Severity:  model.DiagCrit,
								Count:     2,
								Sample:    "Out of memory: Killed process 1234 (mysqld)",
								FirstSeen: time.Now().Add(-5 * time.Minute),
								LastSeen:  time.Now(),
							},
						},
					},
				},
			},
		},
	}

	result := &model.AnalysisResult{Health: model.HealthOK}
	out := renderDiagPage(snap, nil, result, nil, 120, 40)
	vis := stripANSI(out)

	if !strings.Contains(vis, "Crash/restart loop") {
		t.Error("output missing 'Crash/restart loop' label")
	}
	if !strings.Contains(vis, "OOM-killed") {
		t.Error("output missing 'OOM-killed' label")
	}
	if !strings.Contains(vis, "×5") {
		t.Error("output missing crash_restart_loop count '×5'")
	}
	if !strings.Contains(vis, "×2") {
		t.Error("output missing oom_killed count '×2'")
	}
	// Sample line should appear (truncated is fine)
	if !strings.Contains(vis, "main process exited") {
		t.Error("output missing sample text for crash_restart_loop")
	}
	// Severity badge text
	if !strings.Contains(vis, "CRIT") {
		t.Error("output missing CRIT severity badge")
	}
	// Journal section separator
	if !strings.Contains(vis, "Journal findings") {
		t.Error("output missing 'Journal findings' sub-header")
	}
}

// TestRenderDiagPage_NoJournalFindings verifies no extra sections appear
// when a service has no journal findings.
func TestRenderDiagPage_NoJournalFindings(t *testing.T) {
	snap := &model.Snapshot{
		Global: model.GlobalMetrics{
			Diagnostics: model.DiagMetrics{
				Services: []model.ServiceDiag{
					{Name: "redis", Available: true, WorstSev: model.DiagOK, Findings: nil},
				},
			},
			Logs: model.LogMetrics{
				Services: []model.ServiceLogStats{
					{Name: "redis", Findings: nil},
				},
			},
		},
	}
	result := &model.AnalysisResult{Health: model.HealthOK}
	out := renderDiagPage(snap, nil, result, nil, 120, 40)
	vis := stripANSI(out)

	if strings.Contains(vis, "Journal findings") {
		t.Error("unexpected 'Journal findings' section for service with no findings")
	}
	if !strings.Contains(vis, "No findings") {
		t.Error("expected 'No findings' text when service has no findings at all")
	}
}

// TestRenderDiagPage_NilSnap verifies no panic with empty diagnostics.
func TestRenderDiagPage_NilSnap(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("renderDiagPage panicked: %v", r)
		}
	}()
	snap := &model.Snapshot{}
	result := &model.AnalysisResult{}
	out := renderDiagPage(snap, nil, result, nil, 120, 40)
	if out == "" {
		t.Error("renderDiagPage returned empty string")
	}
}
