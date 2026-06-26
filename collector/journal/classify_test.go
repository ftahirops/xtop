package journal_test

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/model"
)

func TestClassifyCrashLoop(t *testing.T) {
	e := []journal.Entry{{Priority: 3, Message: "Start request repeated too quickly for nginx.service", Unit: "nginx.service"}}
	f := journal.Classify(e, 0)
	if len(f) != 1 || f[0].Signature != "crash_restart_loop" || f[0].Severity != model.DiagCrit {
		t.Fatalf("got %+v", f)
	}
}

func TestClassifyOOM(t *testing.T) {
	e := []journal.Entry{{Priority: 2, Message: "Out of memory: Killed process 1234 (mysqld)", Unit: "kernel"}}
	f := journal.Classify(e, 0)
	if len(f) != 1 || f[0].Signature != "oom_killed" || f[0].Severity != model.DiagCrit {
		t.Fatalf("got %+v", f)
	}
}

func TestClassifyNoiseIgnored(t *testing.T) {
	e := []journal.Entry{{Priority: 5, Message: "0 errors during startup"}}
	f := journal.Classify(e, 0)
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %+v", f)
	}
}

func TestClassifyRateSpike(t *testing.T) {
	entries := make([]journal.Entry, 50)
	for i := range entries {
		entries[i] = journal.Entry{Priority: 3, Message: "some critical kernel message"}
	}
	// baselineRate=2, actual count=50, 50 > 3*2=6 → should fire error_rate_spike
	f := journal.Classify(entries, 2)
	found := false
	for _, x := range f {
		if x.Signature == "error_rate_spike" && x.Severity == model.DiagWarn {
			found = true
			if x.Count != 50 {
				t.Errorf("error_rate_spike Count want 50 got %d", x.Count)
			}
		}
	}
	if !found {
		t.Fatalf("expected error_rate_spike finding, got %+v", f)
	}
}

func TestClassifyMixedBatch(t *testing.T) {
	now := time.Now()
	entries := []journal.Entry{
		// crash_restart_loop (crit)
		{Priority: 3, Message: "Main process exited, code=killed, status=9/KILL", Unit: "svc.service", At: now},
		{Priority: 3, Message: "Scheduled restart job for svc.service", Unit: "svc.service", At: now.Add(time.Second)},
		// oom_killed (crit)
		{Priority: 2, Message: "oom-kill action=kill, victim svc", At: now},
		// dependency_failure (warn)
		{Priority: 4, Message: "connection refused: 127.0.0.1:5432", At: now},
		// noise — must not match
		{Priority: 6, Message: "0 errors during startup"},
		{Priority: 6, Message: "service started successfully"},
	}
	f := journal.Classify(entries, 0)

	sigs := map[string]journal.JournalFinding{}
	for _, x := range f {
		sigs[x.Signature] = x
	}

	if _, ok := sigs["crash_restart_loop"]; !ok {
		t.Errorf("missing crash_restart_loop; findings: %+v", f)
	}
	if sigs["crash_restart_loop"].Count != 2 {
		t.Errorf("crash_restart_loop count want 2 got %d", sigs["crash_restart_loop"].Count)
	}
	if _, ok := sigs["oom_killed"]; !ok {
		t.Errorf("missing oom_killed; findings: %+v", f)
	}
	if _, ok := sigs["dependency_failure"]; !ok {
		t.Errorf("missing dependency_failure; findings: %+v", f)
	}
	if len(f) != 3 {
		t.Errorf("expected 3 distinct findings, got %d: %+v", len(f), f)
	}
}

func TestClassifyFirstMatchWins(t *testing.T) {
	// "Out of memory: Killed process" matches oom_killed (crit)
	// but also contains "Killed process" which is in oom_killed anyway.
	// The important test: a line that could match a warn marker but also matches a crit marker
	// must be classified as crit (first match wins crit→warn ordering).
	// "connection refused" is warn. "Fatal error: connection refused" could naively
	// match segfault_panic (via "fatal error:"), test it goes to segfault_panic (crit), not dependency_failure.
	e := []journal.Entry{
		{Priority: 1, Message: "fatal error: connection refused to database"},
	}
	f := journal.Classify(e, 0)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if f[0].Signature != "segfault_panic" {
		t.Errorf("expected segfault_panic (crit first-match), got %s", f[0].Signature)
	}
}

func TestClassifySampleTruncated(t *testing.T) {
	long := "Out of memory: Killed process 1234 (mysqld) total-vm:123456kB, anon-rss:99999kB, file-rss:0kB, shmem-rss:0kB, UID:1000 pgtables:128kB oom_score_adj:0 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	e := []journal.Entry{{Priority: 2, Message: long}}
	f := journal.Classify(e, 0)
	if len(f) != 1 {
		t.Fatalf("got %+v", f)
	}
	if len(f[0].Sample) > 120 {
		t.Errorf("sample not truncated: len=%d", len(f[0].Sample))
	}
}

func TestClassifyTimestamps(t *testing.T) {
	t0 := time.Unix(1000, 0)
	t1 := time.Unix(2000, 0)
	t2 := time.Unix(3000, 0)
	entries := []journal.Entry{
		{Priority: 3, Message: "Main process exited, code=killed", At: t1},
		{Priority: 3, Message: "Failed with result 'exit-code'", At: t0},
		{Priority: 3, Message: "Scheduled restart job", At: t2},
	}
	f := journal.Classify(entries, 0)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !f[0].FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen want %v got %v", t0, f[0].FirstSeen)
	}
	if !f[0].LastSeen.Equal(t2) {
		t.Errorf("LastSeen want %v got %v", t2, f[0].LastSeen)
	}
	if f[0].Count != 3 {
		t.Errorf("Count want 3 got %d", f[0].Count)
	}
}

func TestClassifyBenignUpstreamDNSNotDependencyFailure(t *testing.T) {
	// Test that benign log messages containing "upstream" or "dns" substrings
	// do not incorrectly trigger dependency_failure now that markers are specific.
	entries := []journal.Entry{
		{Priority: 4, Message: "upstream group 'web' added to load balancer config"},
		{Priority: 4, Message: "DNSSEC validation enabled for zone example.com"},
		{Priority: 4, Message: "dns cache statistics: 1000 hits, 50 misses"},
	}
	f := journal.Classify(entries, 0)
	// None of these should produce dependency_failure
	for _, x := range f {
		if x.Signature == "dependency_failure" {
			t.Errorf("benign message incorrectly matched dependency_failure: %s", x.Sample)
		}
	}
	if len(f) != 0 {
		t.Errorf("expected 0 findings for benign messages, got %d: %+v", len(f), f)
	}

	// Now test that genuine failure messages DO match.
	failureEntries := []journal.Entry{
		{Priority: 3, Message: "upstream connect error while connecting to backend server"},
		{Priority: 3, Message: "dns resolution failed: temporary failure"},
		{Priority: 3, Message: "name resolution error for api.example.com"},
	}
	ff := journal.Classify(failureEntries, 0)
	foundFailure := false
	for _, x := range ff {
		if x.Signature == "dependency_failure" {
			foundFailure = true
		}
	}
	if !foundFailure {
		t.Errorf("expected dependency_failure finding for real failure messages, got %+v", ff)
	}
}
