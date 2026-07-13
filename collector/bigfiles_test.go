//go:build linux

package collector

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestWalkDirAggregatesDirectories verifies that walkDir rolls up recursive
// subtree sizes and file counts into the dirs map.
func TestWalkDirAggregatesDirectories(t *testing.T) {
	root := t.TempDir()
	// root/a has two files totalling 300 bytes across a nested dir.
	writeFile(t, filepath.Join(root, "a", "f1"), 100)
	writeFile(t, filepath.Join(root, "a", "deep", "f2"), 200)
	// root/b has one file of 50 bytes.
	writeFile(t, filepath.Join(root, "b", "f3"), 50)

	var files []model.BigFile
	dirs := make(map[string]*dirAgg)
	budget, total, count := walkDir(root, 0, &files, dirs, 3000, 0)

	if budget >= 3000 {
		t.Errorf("expected budget to be consumed, got %d", budget)
	}
	if total != 350 {
		t.Errorf("root subtree bytes = %d, want 350", total)
	}
	if count != 3 {
		t.Errorf("root subtree files = %d, want 3", count)
	}

	a := dirs[filepath.Join(root, "a")]
	if a == nil || a.bytes != 300 || a.files != 2 {
		t.Errorf("dir a agg = %+v, want bytes=300 files=2", a)
	}
	if a.depth != 1 {
		t.Errorf("dir a depth = %d, want 1", a.depth)
	}
	b := dirs[filepath.Join(root, "b")]
	if b == nil || b.bytes != 50 || b.files != 1 {
		t.Errorf("dir b agg = %+v, want bytes=50 files=1", b)
	}
}

// TestTopDirsDisjoint verifies that topDirs skips directories nested under an
// already-selected ancestor and excludes the scan roots (depth 0).
func TestTopDirsDisjoint(t *testing.T) {
	dirs := map[string]*dirAgg{
		"/var/lib":               {bytes: 1000, files: 10, depth: 0}, // root, must be excluded
		"/var/lib/docker":        {bytes: 900, files: 9, depth: 1},   // biggest disjoint
		"/var/lib/docker/volume": {bytes: 800, files: 5, depth: 2},   // nested under docker -> skip
		"/var/lib/mysql":         {bytes: 400, files: 3, depth: 1},   // separate -> include
		"/var/lib/small":         {bytes: 10, files: 1, depth: 1},    // below minSize -> skip
	}

	out := topDirs(dirs, 50, 10)

	if len(out) != 2 {
		t.Fatalf("got %d dirs, want 2: %+v", len(out), out)
	}
	if out[0].Path != "/var/lib/docker" || out[0].SizeBytes != 900 {
		t.Errorf("first = %+v, want /var/lib/docker 900", out[0])
	}
	if out[1].Path != "/var/lib/mysql" || out[1].SizeBytes != 400 {
		t.Errorf("second = %+v, want /var/lib/mysql 400", out[1])
	}
	for _, d := range out {
		if d.Path == "/var/lib" {
			t.Error("scan root /var/lib should be excluded")
		}
		if d.Path == "/var/lib/docker/volume" {
			t.Error("nested /var/lib/docker/volume should be collapsed into parent")
		}
	}
}

// TestTopDirsRespectsMax verifies the result count is capped.
func TestTopDirsRespectsMax(t *testing.T) {
	dirs := map[string]*dirAgg{
		"/x/a": {bytes: 500, files: 1, depth: 1},
		"/x/b": {bytes: 400, files: 1, depth: 1},
		"/x/c": {bytes: 300, files: 1, depth: 1},
	}
	out := topDirs(dirs, 50, 2)
	if len(out) != 2 {
		t.Fatalf("got %d dirs, want 2 (capped)", len(out))
	}
	if out[0].SizeBytes != 500 || out[1].SizeBytes != 400 {
		t.Errorf("expected largest two by size, got %+v", out)
	}
}

// TestWalkDirBudgetExhaustionSignals verifies the walk reports budget
// exhaustion so callers can mark results as a partial (lower-bound) scan
// instead of presenting truncated sizes as authoritative du output.
func TestWalkDirBudgetExhaustionSignals(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		writeFile(t, filepath.Join(root, "d", fmt.Sprintf("f%d", i)), 10)
	}

	var files []model.BigFile
	dirs := make(map[string]*dirAgg)
	budget, _, _ := walkDir(root, 0, &files, dirs, 2, 0)
	if budget > 0 {
		t.Fatalf("expected budget exhausted (<=0), got %d", budget)
	}
}
