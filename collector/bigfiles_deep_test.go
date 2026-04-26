//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// writeFile creates a file of the given byte size. We use truncate so the
// filesystem doesn't actually allocate blocks (sparse) — the walker only
// consults Size() via stat, so sparse files are equivalent to real ones.
func writeFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// newScannerForTest returns a scanner wired to scan only the given subtree,
// with aggressive pacing (no throttling) for determinism.
func newScannerForTest(t *testing.T, root string, minSize uint64) *DeepBigFileScanner {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "state.json")
	d := NewDeepBigFileScanner(DeepScannerConfig{
		MinSize:           minSize,
		MaxResults:        20,
		PauseAtIOPct:      100, // never pause in tests
		ResumeAtIOPct:     0,
		MinFilesPerMinute: 100000,
		StatePath:         statePath,
	})
	// Instead of running from "/", redirect the walk by replacing walkRoot.
	// Our test approach: call topN / state-save / env-config paths directly.
	_ = root
	return d
}

func TestTopN_DescendingSort(t *testing.T) {
	in := []model.BigFile{
		{Path: "/a", SizeBytes: 100},
		{Path: "/b", SizeBytes: 500},
		{Path: "/c", SizeBytes: 300},
		{Path: "/d", SizeBytes: 50},
	}
	got := topN(in, 3)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].SizeBytes != 500 || got[1].SizeBytes != 300 || got[2].SizeBytes != 100 {
		t.Errorf("bad sort: %+v", got)
	}
}

func TestTopN_HandlesSmallInput(t *testing.T) {
	in := []model.BigFile{{Path: "/a", SizeBytes: 10}}
	got := topN(in, 5)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}

func TestDeepScanConfigFromEnv(t *testing.T) {
	t.Setenv("XTOP_SCAN_PAUSE_AT_IOPCT", "42")
	t.Setenv("XTOP_SCAN_RESUME_AT_IOPCT", "11")
	t.Setenv("XTOP_SCAN_MIN_RATE", "250")
	t.Setenv("XTOP_SCAN_MIN_SIZE_MIB", "100")
	t.Setenv("XTOP_SCAN_MAX_RESULTS", "75")
	c := DeepScanConfigFromEnv()
	if c.PauseAtIOPct != 42 {
		t.Errorf("PauseAtIOPct = %v, want 42", c.PauseAtIOPct)
	}
	if c.ResumeAtIOPct != 11 {
		t.Errorf("ResumeAtIOPct = %v, want 11", c.ResumeAtIOPct)
	}
	if c.MinFilesPerMinute != 250 {
		t.Errorf("MinFilesPerMinute = %d, want 250", c.MinFilesPerMinute)
	}
	if c.MinSize != 100*1024*1024 {
		t.Errorf("MinSize = %d, want 100 MiB", c.MinSize)
	}
	if c.MaxResults != 75 {
		t.Errorf("MaxResults = %d, want 75", c.MaxResults)
	}
}

func TestDeepScanConfigFromEnv_IgnoresBadValues(t *testing.T) {
	t.Setenv("XTOP_SCAN_PAUSE_AT_IOPCT", "not-a-number")
	t.Setenv("XTOP_SCAN_MIN_RATE", "-1")
	c := DeepScanConfigFromEnv()
	if c.PauseAtIOPct != 0 {
		t.Errorf("invalid env should leave PauseAtIOPct at zero (default applied in ctor), got %v", c.PauseAtIOPct)
	}
	if c.MinFilesPerMinute != 0 {
		t.Errorf("negative min rate should be ignored: got %d", c.MinFilesPerMinute)
	}
}

func TestDeepScanEnabled(t *testing.T) {
	t.Setenv("XTOP_DEEP_SCAN", "")
	if DeepScanEnabled() {
		t.Error("empty env should not enable")
	}
	t.Setenv("XTOP_DEEP_SCAN", "1")
	if !DeepScanEnabled() {
		t.Error("env=1 should enable")
	}
	t.Setenv("XTOP_DEEP_SCAN", "true")
	if DeepScanEnabled() {
		t.Error("we accept '1' only; 'true' should not enable (keeps behavior unambiguous)")
	}
}

func TestStateSaveAndLoadRoundTrip(t *testing.T) {
	d := newScannerForTest(t, t.TempDir(), 50<<20)
	// Simulate a partial walk's state.
	d.lastPath.Store("/var/log/syslog.3.gz")
	d.fileCount.Store(1234)
	d.scanBytes.Store(9 * 1024 * 1024 * 1024)
	d.passNumber.Store(7)
	d.startedAt = time.Now().Add(-5 * time.Minute).UTC()
	d.stable = []model.BigFile{
		{Path: "/data/huge.bin", SizeBytes: 20 * 1024 * 1024 * 1024, ModTime: time.Now().Unix()},
	}
	d.saveState()

	// Fresh scanner, same state path → should inherit values.
	d2 := NewDeepBigFileScanner(DeepScannerConfig{StatePath: d.statePath})
	d2.loadState()
	if d2.fileCount.Load() != 1234 {
		t.Errorf("fileCount after reload = %d, want 1234", d2.fileCount.Load())
	}
	if d2.passNumber.Load() != 7 {
		t.Errorf("passNumber after reload = %d, want 7", d2.passNumber.Load())
	}
	results := d2.Results()
	if len(results) != 1 || results[0].Path != "/data/huge.bin" {
		t.Errorf("results after reload: %+v", results)
	}
}

func TestThrottle_SkipsWithoutProvider(t *testing.T) {
	d := newScannerForTest(t, t.TempDir(), 50<<20)
	done := make(chan struct{})
	go func() {
		d.throttle()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("throttle without IO provider should return immediately")
	}
}

func TestThrottle_PausesWhenBusy(t *testing.T) {
	d := newScannerForTest(t, t.TempDir(), 50<<20)
	// Simulate an IO-busy system: report 90% util.
	var busy atomic.Int64
	busy.Store(90)
	d.SetIOPctProvider(func() float64 { return float64(busy.Load()) })
	d.pauseAtIOPct = 30
	d.resumeIOPct = 10
	// A short min-rate budget (2400 ms) so the test doesn't take a minute.
	d.minRate = 12500 // 500 files / 12500 per-min = ~2.4 s

	go func() {
		time.Sleep(400 * time.Millisecond)
		// IO goes quiet → throttle should exit promptly.
		busy.Store(5)
	}()

	start := time.Now()
	d.throttle()
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Errorf("throttle returned too fast (%v) — should have paused while busy", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("throttle didn't resume after IO dropped: %v", elapsed)
	}
}

func TestProgress_IsSafeBeforeStart(t *testing.T) {
	d := newScannerForTest(t, t.TempDir(), 50<<20)
	p := d.Progress()
	if p.Running {
		t.Error("unstarted scanner must report Running=false")
	}
	if p.Files != 0 || p.Pass != 0 {
		t.Error("fresh counters should be zero")
	}
	if p.LastPath != "" {
		t.Error("last path should be empty before any work")
	}
}
