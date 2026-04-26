package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// libWithFiles populates a fresh runbook library from inline file contents.
// Uses a temp dir so every test is hermetic.
func libWithFiles(t *testing.T, files map[string]string) *RunbookLibrary {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lib := &RunbookLibrary{
		dir:         dir,
		reloadEvery: time.Hour, // prevent auto-reload during tests
	}
	if err := lib.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	return lib
}

// buildResult is a tiny helper so each test reads: situation → expected match.
func buildResult(bottleneck, app, culprit string, evIDs ...string) *model.AnalysisResult {
	ev := make([]model.Evidence, 0, len(evIDs))
	for _, id := range evIDs {
		ev = append(ev, model.Evidence{ID: id, Strength: 0.7})
	}
	return &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: bottleneck,
		PrimaryProcess:    culprit,
		PrimaryAppName:    app,
		RCA:               []model.RCAEntry{{Bottleneck: bottleneck, EvidenceV2: ev}},
	}
}

func TestRunbook_ParsesFrontmatter(t *testing.T) {
	lib := libWithFiles(t, map[string]string{
		"nginx.md": "---\nname: Nginx workers\nbottleneck: cpu, network\napp: nginx\n---\n## Fix\nreload\n",
	})
	all := lib.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 runbook loaded, got %d", len(all))
	}
	rb := all[0]
	if rb.Name != "Nginx workers" {
		t.Errorf("name = %q, want 'Nginx workers'", rb.Name)
	}
	if len(rb.Match.Bottleneck) != 2 {
		t.Errorf("bottleneck = %v, want 2 entries", rb.Match.Bottleneck)
	}
	if len(rb.Match.AppContains) != 1 || rb.Match.AppContains[0] != "nginx" {
		t.Errorf("app_contains = %v, want [nginx]", rb.Match.AppContains)
	}
}

func TestRunbook_MatchScoresExpectedly(t *testing.T) {
	lib := libWithFiles(t, map[string]string{
		"nginx.md": "---\nbottleneck: cpu\napp: nginx\nevidence: runqlat_high\n---\nbody\n",
		"generic.md": "---\nbottleneck: cpu\n---\ngeneric body\n",
	})
	// Incident: cpu + nginx + runqlat_high firing → nginx runbook should win (4 + 3 + 1 = 8).
	r := buildResult("cpu", "nginx", "nginx", "runqlat_high")
	m := lib.Match(r)
	if m == nil {
		t.Fatal("expected a runbook match")
	}
	if !fileNameEquals(m.Path, "nginx.md") {
		t.Errorf("expected nginx.md to win, got %s (score %d)", m.Path, m.Score)
	}
	if m.Score < 8 {
		t.Errorf("score = %d, want ≥ 8", m.Score)
	}
}

func TestRunbook_DisqualifiedWhenGateFails(t *testing.T) {
	lib := libWithFiles(t, map[string]string{
		"nginx.md": "---\napp: nginx\n---\nfix\n",
	})
	// app is 'redis' — nginx runbook gates on app=nginx and must NOT match.
	r := buildResult("cpu", "redis", "redis-server")
	if got := lib.Match(r); got != nil {
		t.Errorf("expected nil match when app gate fails, got %+v", got)
	}
}

func TestRunbook_NoFrontmatterBecomesFilenameStem(t *testing.T) {
	lib := libWithFiles(t, map[string]string{
		"my-custom.md": "## Notes\nFree-form runbook.\n",
	})
	all := lib.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 loaded, got %d", len(all))
	}
	if all[0].Name != "my-custom" {
		t.Errorf("name fallback = %q, want 'my-custom'", all[0].Name)
	}
	// No matcher → should not match anything; prevents false positives.
	r := buildResult("cpu", "anything", "anything")
	if got := lib.Match(r); got != nil {
		t.Errorf("runbook with empty matcher must not match, got %+v", got)
	}
}

func TestRunbook_PreviewIsSanelyTrimmed(t *testing.T) {
	body := "## Diagnosis\n\nMySQL is the culprit. " +
		"Typical causes include slow queries, small buffer pool, or long transactions. " +
		"Collect evidence with SHOW PROCESSLIST and InnoDB status."
	lib := libWithFiles(t, map[string]string{
		"mysql.md": "---\napp: mysql\n---\n" + body + "\n",
	})
	r := buildResult("io", "mysql", "mysqld")
	m := lib.Match(r)
	if m == nil {
		t.Fatal("expected a match")
	}
	if len(m.Preview) == 0 {
		t.Error("expected non-empty preview")
	}
	if len(m.Preview) > 300 {
		t.Errorf("preview too long (%d chars)", len(m.Preview))
	}
}

func TestRunbook_SignatureBoostsScore(t *testing.T) {
	sig := signatureFromResult(buildResult("cpu", "nginx", "nginx", "runqlat_high"))
	lib := libWithFiles(t, map[string]string{
		"with-sig.md":    "---\nbottleneck: cpu\nsignature: " + sig + "\n---\nfix\n",
		"without-sig.md": "---\nbottleneck: cpu\napp: nginx\nevidence: runqlat_high\n---\nfix\n",
	})
	r := buildResult("cpu", "nginx", "nginx", "runqlat_high")
	m := lib.Match(r)
	if m == nil {
		t.Fatal("expected match")
	}
	if !fileNameEquals(m.Path, "with-sig.md") {
		t.Errorf("signature match should win, got %s (score %d)", m.Path, m.Score)
	}
}

func fileNameEquals(path, name string) bool {
	return filepath.Base(path) == name
}
