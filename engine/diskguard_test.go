package engine

import "testing"

func TestDiskGuardState(t *testing.T) {
	cases := []struct {
		name    string
		freePct float64
		etaSec  float64
		inode   float64
		want    string
	}{
		{"crit_free", 4, -1, 10, "CRIT"},
		{"crit_eta", 20, 1000, 10, "CRIT"},
		{"crit_inode", 20, -1, 96, "CRIT"},
		{"warn_free", 10, -1, 10, "WARN"},
		{"warn_eta", 20, 4000, 10, "WARN"},
		{"warn_inode", 20, -1, 86, "WARN"},
		{"ok", 50, -1, 10, "OK"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := diskGuardState(c.freePct, c.etaSec, c.inode); got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestWorstDiskGuardState(t *testing.T) {
	if got := WorstDiskGuardState(nil); got != "OK" {
		t.Fatalf("expected OK, got %s", got)
	}
}
