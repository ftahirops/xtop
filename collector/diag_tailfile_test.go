package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTmp creates a temp file with the given content and returns its path.
func writeTmp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeTmp: %v", err)
	}
	return path
}

func TestTailFile(t *testing.T) {
	t.Run("n_less_than_M", func(t *testing.T) {
		// 10 lines, ask for last 4.
		lines := make([]string, 10)
		for i := range lines {
			lines[i] = fmt.Sprintf("line%02d", i+1)
		}
		path := writeTmp(t, "basic.log", strings.Join(lines, "\n")+"\n")
		got := tailFile(path, 4)
		want := []string{"line07", "line08", "line09", "line10"}
		assertLines(t, got, want)
	})

	t.Run("n_equals_M", func(t *testing.T) {
		lines := []string{"alpha", "beta", "gamma"}
		path := writeTmp(t, "eq.log", strings.Join(lines, "\n")+"\n")
		got := tailFile(path, 3)
		assertLines(t, got, lines)
	})

	t.Run("n_greater_than_M", func(t *testing.T) {
		lines := []string{"only", "two"}
		path := writeTmp(t, "small.log", strings.Join(lines, "\n")+"\n")
		got := tailFile(path, 100)
		assertLines(t, got, lines)
	})

	t.Run("empty_file", func(t *testing.T) {
		path := writeTmp(t, "empty.log", "")
		got := tailFile(path, 10)
		if got != nil {
			t.Fatalf("empty file: want nil, got %v", got)
		}
	})

	t.Run("no_trailing_newline", func(t *testing.T) {
		// The last line has no \n — it must still be returned.
		content := "first\nsecond\nthird" // no trailing newline
		path := writeTmp(t, "noeol.log", content)
		got := tailFile(path, 2)
		want := []string{"second", "third"}
		assertLines(t, got, want)
	})

	t.Run("single_line_no_newline", func(t *testing.T) {
		path := writeTmp(t, "one.log", "hello")
		got := tailFile(path, 5)
		assertLines(t, got, []string{"hello"})
	})

	t.Run("single_line_with_newline", func(t *testing.T) {
		path := writeTmp(t, "onenl.log", "hello\n")
		got := tailFile(path, 5)
		assertLines(t, got, []string{"hello"})
	})

	t.Run("large_file_seek_path", func(t *testing.T) {
		// Write ~4 MB of lines so the file exceeds the 64 KB fast-path threshold.
		// Each line is "XXXX line NNNNN\n" (~20 bytes); 200 000 lines ≈ 4 MB.
		const totalLines = 200_000
		var sb strings.Builder
		sb.Grow(totalLines * 20)
		for i := 1; i <= totalLines; i++ {
			fmt.Fprintf(&sb, "XXXX line %06d\n", i)
		}
		path := writeTmp(t, "large.log", sb.String())

		got := tailFile(path, 10)
		// Expected: last 10 lines (190001..200000)
		want := make([]string, 10)
		for i := 0; i < 10; i++ {
			want[i] = fmt.Sprintf("XXXX line %06d", totalLines-9+i)
		}
		assertLines(t, got, want)
	})

	t.Run("n_zero", func(t *testing.T) {
		path := writeTmp(t, "nz.log", "a\nb\n")
		got := tailFile(path, 0)
		if got != nil {
			t.Fatalf("n=0: want nil, got %v", got)
		}
	})

	t.Run("nonexistent_file", func(t *testing.T) {
		got := tailFile("/nonexistent/path/that/does/not/exist.log", 10)
		if got != nil {
			t.Fatalf("missing file: want nil, got %v", got)
		}
	})

	t.Run("only_newlines", func(t *testing.T) {
		// A file containing only newlines — every "line" is empty.
		path := writeTmp(t, "newlines.log", "\n\n\n")
		got := tailFile(path, 2)
		// bytes.Split("\n\n" [after trim], "\n") = ["", ""]
		want := []string{"", ""}
		assertLines(t, got, want)
	})
}

// assertLines checks that got matches want exactly (length + content + order).
func assertLines(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("line count: got %d, want %d\n  got:  %v\n  want: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}
