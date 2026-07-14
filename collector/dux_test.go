//go:build linux

package collector

import "testing"

// Real `dux top --json` output shape (dux 0.5.2).
const duxTopJSON = `[
  {"bytes": 42479112192, "inodes": 347246, "kind": "dir", "mtime": 1782986988, "path": "/home"},
  {"bytes": 147949282816, "inodes": 1669441, "kind": "dir", "mtime": 1779826740, "path": "/"},
  {"bytes": 8608407552, "inodes": 1, "kind": "file", "mtime": 1782757577, "path": "/var/lib/xhelix/cold.db"}
]`

// Real `dux growth --json` output shape. "inode:NNN" rows are entries whose
// path could not be resolved — useless to display, must be filtered.
const duxGrowthJSON = `[
  {"delta_bytes": 68132864, "path": "/tmp/go-build669811604/b001/service.test"},
  {"delta_bytes": 37281792, "path": "inode:265307"},
  {"delta_bytes": 21282816, "path": "/var/log/vault/audit.log"}
]`

func TestParseDuxRows(t *testing.T) {
	rows, err := parseDuxRows([]byte(duxTopJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if rows[0].Path != "/home" || rows[0].Bytes != 42479112192 || rows[0].Inodes != 347246 {
		t.Fatalf("row 0 mismatch: %+v", rows[0])
	}
	if rows[2].Kind != "file" || rows[2].Mtime != 1782757577 {
		t.Fatalf("row 2 mismatch: %+v", rows[2])
	}
}

// The root "/" row is "everything on the filesystem" — noise in a top-dirs
// list; duxDirsFromRows must drop it and convert the rest.
func TestDuxDirsFromRowsSkipsRoot(t *testing.T) {
	rows, err := parseDuxRows([]byte(duxTopJSON))
	if err != nil {
		t.Fatal(err)
	}
	dirs := duxDirsFromRows(rows)
	for _, d := range dirs {
		if d.Path == "/" {
			t.Fatal("root row must be dropped from top dirs")
		}
	}
	if len(dirs) == 0 || dirs[0].Path != "/home" || dirs[0].SizeBytes != 42479112192 || dirs[0].FileCount != 347246 {
		t.Fatalf("converted dirs wrong: %+v", dirs)
	}
}

func TestParseDuxGrowthFiltersUnresolved(t *testing.T) {
	entries, err := parseDuxGrowth([]byte(duxGrowthJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (inode:NNN row filtered)", len(entries))
	}
	if entries[0].Path != "/tmp/go-build669811604/b001/service.test" || entries[0].DeltaBytes != 68132864 {
		t.Fatalf("entry 0 mismatch: %+v", entries[0])
	}
	for _, e := range entries {
		if len(e.Path) > 6 && e.Path[:6] == "inode:" {
			t.Fatalf("unresolved inode row leaked: %+v", e)
		}
	}
}

func TestParseDuxRowsBadJSON(t *testing.T) {
	if _, err := parseDuxRows([]byte("not json")); err == nil {
		t.Fatal("expected error on malformed input")
	}
}
