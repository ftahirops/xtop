package configdrift_test

import (
	"strings"
	"testing"

	"github.com/ftahirops/xtop/collector/configdrift"
)

// ---------------------------------------------------------------------------
// THP parser
// ---------------------------------------------------------------------------

func TestParseTHP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"[madvise] never always", "madvise"},
		{"always [never]", "never"},
		{"always [madvise] never", "madvise"},
		// no brackets — return trimmed value as-is
		{"madvise", "madvise"},
		{"never", "never"},
	}
	for _, c := range cases {
		got := configdrift.ParseTHP(c.in)
		if got != c.want {
			t.Errorf("ParseTHP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Default TrimSpace normalization
// ---------------------------------------------------------------------------

func TestTrimSpaceNorm(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"  60\n", "60"},
		{"0\t", "0"},
		{"1", "1"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(c.in)
		if got != c.want {
			t.Errorf("TrimSpace(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Keys registry invariants
// ---------------------------------------------------------------------------

var allowedDomains = map[string]bool{
	"memory":  true,
	"cpu":     true,
	"network": true,
	"io":      true,
	"limits":  true,
}

func TestKeysRegistry(t *testing.T) {
	if len(configdrift.Keys) == 0 {
		t.Fatal("Keys must be non-empty")
	}
	seen := map[string]bool{}
	for i, k := range configdrift.Keys {
		if k.Name == "" {
			t.Errorf("Keys[%d].Name is empty", i)
		}
		if k.Domain == "" {
			t.Errorf("Keys[%d] (%s) Domain is empty", i, k.Name)
		}
		if k.Path == "" {
			t.Errorf("Keys[%d] (%s) Path is empty", i, k.Name)
		}
		if k.Parse == nil {
			t.Errorf("Keys[%d] (%s) Parse is nil", i, k.Name)
		}
		if !allowedDomains[k.Domain] {
			t.Errorf("Keys[%d] (%s) has unknown Domain %q", i, k.Name, k.Domain)
		}
		if seen[k.Name] {
			t.Errorf("duplicate key Name %q", k.Name)
		}
		seen[k.Name] = true
	}
}
