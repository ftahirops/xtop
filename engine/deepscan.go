package engine

import (
	"sync/atomic"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/model"
)

// currentIOPct is a shared atomic the engine updates each tick and the deep
// scanner reads for adaptive pacing. We use a uint64 bitcast because
// atomic.Float64 doesn't land until Go 1.22+ and we want portability.
var currentIOPctBits atomic.Uint64

func setCurrentIOPct(pct float64) {
	currentIOPctBits.Store(math_Float64bits(pct))
}

func getCurrentIOPct() float64 {
	return math_Float64frombits(currentIOPctBits.Load())
}

// buildDeepScanner constructs the scanner when the operator has opted in.
// Returns nil when disabled so engine.Tick() can cheaply skip the feature.
func buildDeepScanner() *collector.DeepBigFileScanner {
	if !collector.DeepScanEnabled() {
		return nil
	}
	s := collector.NewDeepBigFileScanner(collector.DeepScanConfigFromEnv())
	s.SetIOPctProvider(getCurrentIOPct)
	s.Start()
	return s
}

// mergeDeepScanResults overlays the deep scanner's findings on top of the
// quick BigFileCollector's output. Deep results take precedence because
// they come from a full-filesystem walk, but any "fresh-but-not-yet-seen"
// file from the fast collector is preserved so we never LOSE entries.
func mergeDeepScanResults(snap *model.Snapshot, ds *collector.DeepBigFileScanner) {
	if ds == nil {
		return
	}
	deep := ds.Results()
	if len(deep) == 0 {
		return
	}
	// Dedupe by path.
	seen := make(map[string]bool, len(deep))
	merged := make([]model.BigFile, 0, len(deep)+len(snap.Global.BigFiles))
	for _, f := range deep {
		if seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		merged = append(merged, f)
	}
	for _, f := range snap.Global.BigFiles {
		if seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		merged = append(merged, f)
	}
	snap.Global.BigFiles = merged
}

// math_Float64bits / math_Float64frombits wrappers — avoiding "math" import
// here keeps a single source of truth for the conversion helper even though
// the stdlib math.Float64bits would also work.
func math_Float64bits(f float64) uint64 {
	// Go's encoding/binary doesn't export this neatly; just delegate to the
	// tiny stdlib helper. We keep the wrapper so tests can stub if needed.
	return math_fl64bits(f)
}

func math_Float64frombits(u uint64) float64 {
	return math_fl64frombits(u)
}
