package collector

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/model"
)

// JournalRCAMode controls the scope of Tier-2 periodic journal RCA.
// Valid values: "critical" (default), "all", "off".
// Set this before the first collect cycle (e.g. from a CLI flag).
var JournalRCAMode = "critical"

// LogsCollector gathers per-service error/warning rates from journald.
type LogsCollector struct {
	trackedUnits  []string
	discovered    bool
	lastCollect   time.Time
	lastQuery     time.Time // #7: rate-limit journalctl queries
	lastDiscover  time.Time // #25: re-discover periodically
	history       map[string]*logHistory

	// tier2QueryFn is injectable for tests; defaults to journal.Query at collect time.
	tier2QueryFn func(ctx context.Context, unit string, since time.Time) ([]journal.Entry, error)
}

type logHistory struct {
	totalErrors int
	totalWarns  int
	lastError   string
	ringBuf     []float64 // 60 entries for sparkline
	ringIdx     uint64    // #33: use uint64 to prevent overflow on 32-bit
	lastErrors  int       // cached from last query
	lastWarns   int       // cached from last query
	lastErrLine string    // cached from last query
	// Tier-2: track high-priority entry count per window for baseline spike detection.
	highPrioHistory []float64 // 10-entry ring: recent hi-prio counts per cycle
	hpIdx           uint64
}

// highPrioBaseline returns the mean of the non-zero high-priority counts in the
// ring buffer, giving a per-window baseline rate for rate-spike detection.
func (h *logHistory) highPrioBaseline() float64 {
	var sum float64
	var n int
	for _, v := range h.highPrioHistory {
		if v > 0 {
			sum += v
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// knownUnits lists well-known service units to look for.
var knownUnits = []string{
	"nginx", "apache2", "httpd",
	"mysql", "mysqld", "mariadb",
	"postgresql", "postgres",
	"redis", "redis-server",
	"docker", "containerd",
	"sshd", "ssh",
	"kubelet",
	"mongod",
	"memcached",
	"rabbitmq-server",
	"elasticsearch",
	"php-fpm",
	"haproxy",
	"named", "bind9",
	"postfix",
}

func (l *LogsCollector) Name() string { return "logs" }

func (l *LogsCollector) Collect(snap *model.Snapshot) error {
	if l.history == nil {
		l.history = make(map[string]*logHistory)
	}
	if l.tier2QueryFn == nil {
		l.tier2QueryFn = journal.Query
	}

	if !l.discovered {
		l.discoverServices()
		l.discovered = true
		l.lastDiscover = time.Now()
	}

	// #25: Re-discover services every 5 minutes
	if time.Since(l.lastDiscover) >= 5*time.Minute {
		l.discoverServices()
		l.lastDiscover = time.Now()
	}

	now := time.Now()
	deltaS := now.Sub(l.lastCollect).Seconds()
	if deltaS < 0.5 {
		deltaS = 1
	}
	l.lastCollect = now

	// #7: Only query journalctl every 5 seconds to reduce fork storm
	shouldQuery := now.Sub(l.lastQuery) >= 5*time.Second
	querySinceSec := int(now.Sub(l.lastQuery).Seconds()) + 1
	if shouldQuery {
		l.lastQuery = now
	}

	mode := JournalRCAMode // read once; safe because set before engine starts

	var services []model.ServiceLogStats
	for _, unit := range l.trackedUnits {
		h := l.history[unit]
		if h == nil {
			h = &logHistory{
				ringBuf:         make([]float64, 60),
				highPrioHistory: make([]float64, 10),
			}
			l.history[unit] = h
		}
		// Ensure highPrioHistory is allocated for units seeded before this field existed.
		if h.highPrioHistory == nil {
			h.highPrioHistory = make([]float64, 10)
		}

		if shouldQuery {
			errors, warns, lastErr := l.queryJournal(unit, querySinceSec)
			h.lastErrors = errors
			h.lastWarns = warns
			h.lastErrLine = lastErr
			h.totalErrors += errors
			h.totalWarns += warns
			if lastErr != "" {
				h.lastError = lastErr
			}
		}

		errRate := float64(h.lastErrors) / deltaS
		warnRate := float64(h.lastWarns) / deltaS

		// Update ring buffer (#33: safe modulo with uint64)
		h.ringBuf[h.ringIdx%60] = errRate
		h.ringIdx++

		// Build display name
		name := unit
		if strings.HasSuffix(name, ".service") {
			name = strings.TrimSuffix(name, ".service")
		}

		svc := model.ServiceLogStats{
			Name:        name,
			Unit:        unit,
			ErrorRate:   errRate,
			WarnRate:    warnRate,
			TotalErrors: h.totalErrors,
			TotalWarns:  h.totalWarns,
			LastError:   h.lastError,
			RateHistory: copyRing(h.ringBuf, h.ringIdx),
		}

		// Tier-2: structured journal RCA for tracked units.
		if shouldQuery && mode != "off" {
			svc.Findings = l.tier2Scan(unit, h, querySinceSec)
		}

		services = append(services, svc)
	}

	snap.Global.Logs.Services = services
	return nil
}

// tier2Scan runs journal.Query + journal.Classify for one tracked unit and
// returns findings only when a signature fires OR a rate spike is detected.
// Returns nil when the service is quiet (emit-only-on-signal).
//
// querySinceSec is the look-back window in seconds (matches the existing cadence).
func (l *LogsCollector) tier2Scan(unit string, h *logHistory, querySinceSec int) []model.JournalFinding {
	return tier2ScanWith(l.tier2QueryFn, unit, h, querySinceSec)
}

// tier2ScanWith is the pure/injectable core of the Tier-2 scan, factored out
// so tests can inject a stub queryFn without a real LogsCollector.
func tier2ScanWith(
	queryFn func(ctx context.Context, unit string, since time.Time) ([]journal.Entry, error),
	unit string,
	h *logHistory,
	querySinceSec int,
) []model.JournalFinding {
	since := time.Now().Add(-time.Duration(querySinceSec) * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	entries, err := queryFn(ctx, unit, since)
	if err != nil || len(entries) == 0 {
		return nil
	}

	baseline := h.highPrioBaseline()
	raw := journal.Classify(entries, baseline)

	// Update high-priority count ring for next cycle's baseline.
	var hpCount float64
	for _, e := range entries {
		if e.Priority <= 3 {
			hpCount++
		}
	}
	h.highPrioHistory[h.hpIdx%10] = hpCount
	h.hpIdx++

	if len(raw) == 0 {
		return nil
	}

	// Convert journal.JournalFinding → model.JournalFinding.
	out := make([]model.JournalFinding, len(raw))
	for i, f := range raw {
		out[i] = model.JournalFinding{
			Signature: f.Signature,
			Severity:  model.DiagSeverity(f.Severity),
			Count:     f.Count,
			Sample:    f.Sample,
			PID:       f.PID,
			FirstSeen: f.FirstSeen,
			LastSeen:  f.LastSeen,
		}
	}
	return out
}

func (l *LogsCollector) discoverServices() {
	// #37: Use single systemctl call instead of N sequential calls
	out, err := exec.Command("systemctl", "list-units", "--type=service",
		"--state=active", "--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		// Fallback to individual checks
		l.discoverServicesFallback()
		return
	}

	activeUnits := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			activeUnits[fields[0]] = true
		}
	}

	l.trackedUnits = nil

	// In "all" mode, track every discovered active service unit.
	if JournalRCAMode == "all" {
		for unit := range activeUnits {
			if strings.HasSuffix(unit, ".service") {
				l.trackedUnits = append(l.trackedUnits, unit)
			}
		}
	} else {
		for _, name := range knownUnits {
			unit := name + ".service"
			if activeUnits[unit] {
				l.trackedUnits = append(l.trackedUnits, unit)
			}
		}
	}

	// Prune history for services no longer tracked
	l.pruneHistory()
}

func (l *LogsCollector) discoverServicesFallback() {
	l.trackedUnits = nil
	for _, name := range knownUnits {
		unit := name + ".service"
		out, err := exec.Command("systemctl", "is-active", unit).Output()
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(out)) == "active" {
			l.trackedUnits = append(l.trackedUnits, unit)
		}
	}

	// Prune history for services no longer tracked
	l.pruneHistory()
}

// errorKeywords matches case-insensitively against log lines.
var errorKeywords = []string{"error", "fatal", "crit", "fail", "panic"}
var warnKeywords = []string{"warn"}

func (l *LogsCollector) queryJournal(unit string, sinceSec int) (errors, warns int, lastErr string) {
	since := time.Now().Add(-time.Duration(sinceSec) * time.Second).Format("2006-01-02 15:04:05")
	out, err := exec.Command("journalctl", "-u", unit,
		"--since", since, "--no-pager", "-o", "cat").Output()
	if err != nil || len(out) == 0 {
		return 0, 0, ""
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		isErr := false
		for _, kw := range errorKeywords {
			if strings.Contains(lower, kw) {
				errors++
				isErr = true
				break
			}
		}
		if isErr {
			if len(line) > 80 {
				lastErr = line[:80]
			} else {
				lastErr = line
			}
			continue
		}
		for _, kw := range warnKeywords {
			if strings.Contains(lower, kw) {
				warns++
				break
			}
		}
	}
	return
}

// pruneHistory removes history entries for services no longer in trackedUnits.
// This prevents the history map from growing unbounded when services are removed.
func (l *LogsCollector) pruneHistory() {
	if l.history == nil {
		return
	}

	// Build a map of currently tracked units for O(1) lookup
	tracked := make(map[string]struct{}, len(l.trackedUnits))
	for _, u := range l.trackedUnits {
		tracked[u] = struct{}{}
	}

	// Remove any history entries not in the tracked set
	for u := range l.history {
		if _, ok := tracked[u]; !ok {
			delete(l.history, u)
		}
	}
}

func copyRing(buf []float64, idx uint64) []float64 {
	n := uint64(len(buf))
	out := make([]float64, n)
	for i := uint64(0); i < n; i++ {
		out[i] = buf[(idx+i)%n]
	}
	return out
}
