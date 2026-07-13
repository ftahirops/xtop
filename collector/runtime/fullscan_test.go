//go:build linux

package runtime

import (
	"os"
	"testing"
)

// The runtime census used to Detect() over snap.Processes — the top-50 sample —
// so idle interpreters were invisible ("Node.js (1 procs)" vs 9 real). The
// census must scan all of /proc. scanAllComms is that scan: it must at minimum
// see the current process with its real comm.
func TestScanAllCommsSeesEveryProcess(t *testing.T) {
	procs := scanAllComms()
	self := os.Getpid()
	found := false
	for _, p := range procs {
		if p.PID == self && p.Comm != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("scanAllComms did not include our own PID %d (%d procs returned)", self, len(procs))
	}
}
