package engine

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// DomainPacks maps RCA bottleneck names to probe packs.
var DomainPacks = map[string][]string{
	BottleneckCPU:     {"offcpu", "runqlat", "syscalldissect"},
	BottleneckIO:      {"iolatency", "wbstall"},
	BottleneckNetwork: {"tcprtt", "netthroughput", "sockio"},
	BottleneckMemory:  {"pgfault", "swapevict"},
}

// WatchdogTrigger monitors RCA results and auto-triggers domain probes
// when a bottleneck is detected with sufficient confidence.
type WatchdogTrigger struct {
	lastTrigger time.Time
	cooldown    time.Duration
	minScore    int
}

// NewWatchdogTrigger creates a new watchdog trigger with defaults.
func NewWatchdogTrigger() *WatchdogTrigger {
	return &WatchdogTrigger{
		cooldown: 60 * time.Second,
		minScore: 50,
	}
}

// Check returns the domain name if the watchdog should trigger, "" otherwise.
func (w *WatchdogTrigger) Check(result *model.AnalysisResult) string {
	if result == nil {
		return ""
	}
	if result.PrimaryScore < w.minScore {
		return ""
	}
	if time.Since(w.lastTrigger) < w.cooldown {
		return ""
	}
	domain := result.PrimaryBottleneck
	if _, ok := DomainPacks[domain]; !ok {
		return ""
	}
	w.lastTrigger = time.Now()
	return domain
}
