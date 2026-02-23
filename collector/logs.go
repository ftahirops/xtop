package collector

import (
	"os/exec"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// LogsCollector gathers per-service error/warning rates from journald.
type LogsCollector struct {
	trackedUnits  []string
	discovered    bool
	lastCollect   time.Time
	lastQuery     time.Time // #7: rate-limit journalctl queries
	lastDiscover  time.Time // #25: re-discover periodically
	history       map[string]*logHistory
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

	var services []model.ServiceLogStats
	for _, unit := range l.trackedUnits {
		h := l.history[unit]
		if h == nil {
			h = &logHistory{ringBuf: make([]float64, 60)}
			l.history[unit] = h
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

		services = append(services, model.ServiceLogStats{
			Name:        name,
			Unit:        unit,
			ErrorRate:   errRate,
			WarnRate:    warnRate,
			TotalErrors: h.totalErrors,
			TotalWarns:  h.totalWarns,
			LastError:   h.lastError,
			RateHistory: copyRing(h.ringBuf, h.ringIdx),
		})
	}

	snap.Global.Logs.Services = services
	return nil
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
	for _, name := range knownUnits {
		unit := name + ".service"
		if activeUnits[unit] {
			l.trackedUnits = append(l.trackedUnits, unit)
		}
	}
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

func copyRing(buf []float64, idx uint64) []float64 {
	n := uint64(len(buf))
	out := make([]float64, n)
	for i := uint64(0); i < n; i++ {
		out[i] = buf[(idx+i)%n]
	}
	return out
}
