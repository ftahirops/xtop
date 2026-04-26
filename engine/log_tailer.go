package engine

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// LogTailer correlates an active incident's RCA verdict with the application's
// own log output. When RCA points at mysqld, we show mysql's slow-query
// output; when it points at nginx, we surface the latest "upstream timed out"
// errors. This is the single highest-signal cross-reference an operator can
// get without switching terminals.
//
// Design:
//   - Watchlist maps app name → list of candidate log paths + severity regex.
//   - Tailer reads only the last ~64 KiB of each file (seek-from-end) per scan.
//   - Scans are rate-limited to once every 10 s and bounded to 25 ms total
//     wall-clock per tick, so a badly-behaved log never slows collection.
//   - Systemd journal fallback: when no path matches, we fall back to
//     `journalctl -u <culprit> --since=2m --no-pager --lines=200`.
//
// Privacy: we deliberately don't fingerprint log content or send log lines
// to the fleet hub. Excerpts live only on the local AnalysisResult.
type LogTailer struct {
	mu          sync.Mutex
	watches     map[string]appLogConfig
	lastScan    map[string]time.Time
	rateLimit   time.Duration
	maxLinesPer int
	maxPerTick  time.Duration
}

type appLogConfig struct {
	// Aliases lets us match on process name, app identity, or a substring of
	// PrimaryAppName — all lowercased.
	Aliases []string
	Paths   []string
	// Severity keeps the regex compile-time constant per app.
	Severity *regexp.Regexp
	// Extract pulls the useful payload from the line — strips prefixes like
	// timestamps so the excerpt is compact. Nil means "keep the full line."
	Extract func(string) string
	// SystemdUnits are checked with journalctl when the file paths miss.
	SystemdUnits []string
}

// NewLogTailer returns a tailer pre-loaded with the built-in watchlist.
func NewLogTailer() *LogTailer {
	severity := func(pat string) *regexp.Regexp {
		return regexp.MustCompile(`(?i)` + pat)
	}
	t := &LogTailer{
		rateLimit:   10 * time.Second,
		maxLinesPer: 5,
		maxPerTick:  25 * time.Millisecond,
		lastScan:    make(map[string]time.Time),
	}
	t.watches = map[string]appLogConfig{
		"nginx": {
			Aliases: []string{"nginx"},
			Paths:   []string{"/var/log/nginx/error.log"},
			Severity: severity(`\b(error|crit|emerg|alert|upstream timed out|upstream prematurely closed|connection refused|too many open files|worker_connections|no live upstreams)\b`),
			SystemdUnits: []string{"nginx.service"},
		},
		"apache": {
			Aliases: []string{"apache", "apache2", "httpd"},
			Paths:   []string{"/var/log/apache2/error.log", "/var/log/httpd/error_log"},
			Severity: severity(`\b(error|crit|emerg|alert|timeout|segfault|out of memory)\b`),
			SystemdUnits: []string{"apache2.service", "httpd.service"},
		},
		"mysql": {
			Aliases: []string{"mysql", "mariadb", "mysqld", "mariadbd"},
			Paths: []string{
				"/var/log/mysql/error.log",
				"/var/log/mysql/mysql-slow.log",
				"/var/log/mariadb/mariadb.log",
				"/var/log/mysqld.log",
			},
			Severity: severity(`\b(error|warning|aborted|slow query|deadlock|oom|cannot allocate|too many connections|innodb)\b`),
			SystemdUnits: []string{"mysql.service", "mariadb.service", "mysqld.service"},
		},
		"postgres": {
			Aliases: []string{"postgres", "postgresql", "postgres/pgbouncer"},
			Paths: []string{
				"/var/log/postgresql/postgresql.log",
			},
			Severity: severity(`\b(error|fatal|panic|warning|slow|lock wait timeout|deadlock|autovacuum|canceling statement)\b`),
			SystemdUnits: []string{"postgresql.service"},
		},
		"redis": {
			Aliases: []string{"redis", "redis-server"},
			Paths:   []string{"/var/log/redis/redis-server.log", "/var/log/redis/redis.log"},
			Severity: severity(`\b(warning|error|oom|maxmemory|slow log|rewriteaof|aof|rdb error|fork)\b`),
			SystemdUnits: []string{"redis-server.service", "redis.service"},
		},
		"elasticsearch": {
			Aliases: []string{"elasticsearch", "elastic", "java"},
			Paths:   []string{"/var/log/elasticsearch/elasticsearch.log"},
			Severity: severity(`\b(error|warn|fatal|out of memory|heap|too many requests|master not discovered|circuit_breaking)\b`),
			SystemdUnits: []string{"elasticsearch.service"},
		},
		"docker": {
			Aliases: []string{"docker", "dockerd", "containerd"},
			Paths:   []string{"/var/log/docker.log"},
			Severity: severity(`\b(error|warn|level=error|level=fatal|failed to|cannot allocate|oom)\b`),
			SystemdUnits: []string{"docker.service", "containerd.service"},
		},
	}
	// Paths can be expanded at load time (e.g. glob /etc/postgresql/*/main/log/),
	// but for now we match on exact paths plus the systemd-journal fallback.
	// Glob discovery is an easy follow-up if deployments demand it.
	return t
}

// Flush drops the rate-limit cache so the next Observe re-scans from
// scratch. Called by the Guardian when memory pressure forces a cache
// purge. Cheap (map-clear) and safe — worst case is one extra scan on
// the next active-incident tick.
func (t *LogTailer) Flush() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastScan = make(map[string]time.Time)
}

// Observe returns a list of log excerpts relevant to the current incident, or
// nil when there's nothing worth attaching. Must be cheap — it is called on
// every Tick while an incident is active.
func (t *LogTailer) Observe(result *model.AnalysisResult) []model.LogExcerpt {
	if t == nil || result == nil || result.Health == model.HealthOK {
		return nil
	}
	app := strings.ToLower(result.PrimaryAppName)
	culprit := strings.ToLower(result.PrimaryProcess)

	cfg, key := t.pickWatch(app, culprit)
	if key == "" {
		return nil
	}

	t.mu.Lock()
	if time.Since(t.lastScan[key]) < t.rateLimit {
		t.mu.Unlock()
		return nil
	}
	t.lastScan[key] = time.Now()
	t.mu.Unlock()

	deadline := time.Now().Add(t.maxPerTick)
	var out []model.LogExcerpt

	for _, path := range cfg.Paths {
		if time.Now().After(deadline) {
			break
		}
		excerpts := tailMatching(path, key, cfg, t.maxLinesPer)
		out = append(out, excerpts...)
		if len(out) >= t.maxLinesPer {
			break
		}
	}
	// Systemd journal fallback when log files missed. Only spend remaining
	// budget here — journalctl can be slow on busy systems.
	if len(out) == 0 && !time.Now().After(deadline) {
		out = append(out, journalctlExcerpts(key, cfg, t.maxLinesPer)...)
	}
	// Trim to maxLinesPer overall.
	if len(out) > t.maxLinesPer {
		out = out[:t.maxLinesPer]
	}
	return out
}

// pickWatch returns the best matching config for the current app/culprit,
// along with its lookup key (used for rate-limit bookkeeping).
func (t *LogTailer) pickWatch(app, culprit string) (appLogConfig, string) {
	hay := app + " " + culprit
	for name, cfg := range t.watches {
		for _, alias := range cfg.Aliases {
			if alias != "" && strings.Contains(hay, alias) {
				return cfg, name
			}
		}
	}
	return appLogConfig{}, ""
}

// tailMatching reads the last ~64 KiB of `path` and returns lines whose
// regex-severity matches. Each returned excerpt is trimmed of ANSI escapes
// and capped at 240 chars so one malformed log line can't break the UI.
func tailMatching(path, app string, cfg appLogConfig, max int) []model.LogExcerpt {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	const tailBytes = 64 * 1024
	start := int64(0)
	if info.Size() > tailBytes {
		start = info.Size() - tailBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 16*1024), 16*1024)

	// Drop the first (possibly partial) line when we seeked past the start.
	if start > 0 {
		_ = sc.Scan()
	}

	// Keep a sliding window of matches so we end up with the most recent N.
	matches := make([]string, 0, max*2)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if cfg.Severity != nil && !cfg.Severity.MatchString(line) {
			continue
		}
		matches = append(matches, line)
		if len(matches) > max*2 {
			matches = matches[len(matches)-max*2:]
		}
	}
	// Take the tail (most recent) of the collected matches.
	if len(matches) > max {
		matches = matches[len(matches)-max:]
	}

	out := make([]model.LogExcerpt, 0, len(matches))
	for _, raw := range matches {
		line := stripANSI(strings.TrimSpace(raw))
		if cfg.Extract != nil {
			line = cfg.Extract(line)
		}
		line = clampLine(line, 240)
		sev := detectSeverity(line)
		out = append(out, model.LogExcerpt{
			App:      app,
			Path:     path,
			Line:     line,
			Severity: sev,
		})
	}
	return out
}

// journalctlExcerpts runs `journalctl -u <unit> --since=2m` for each unit and
// filters lines by severity regex. Used as a fallback when the app writes to
// the journal rather than a file (e.g. systemd-managed services).
func journalctlExcerpts(app string, cfg appLogConfig, max int) []model.LogExcerpt {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}
	var out []model.LogExcerpt
	for _, unit := range cfg.SystemdUnits {
		if len(out) >= max {
			break
		}
		cmd := exec.Command("journalctl",
			"-u", unit,
			"--since", "2 minutes ago",
			"--no-pager",
			"--output", "cat",
			"--lines", "200",
		)
		// Short deadline — journalctl can stall on slow journals.
		done := make(chan []byte, 1)
		errCh := make(chan error, 1)
		go func() {
			data, err := cmd.Output()
			if err != nil {
				errCh <- err
				return
			}
			done <- data
		}()
		var data []byte
		select {
		case data = <-done:
		case <-errCh:
			continue
		case <-time.After(800 * time.Millisecond):
			_ = cmd.Process.Kill()
			continue
		}
		for _, raw := range bytes.Split(data, []byte("\n")) {
			line := strings.TrimSpace(string(raw))
			if line == "" {
				continue
			}
			if cfg.Severity != nil && !cfg.Severity.MatchString(line) {
				continue
			}
			out = append(out, model.LogExcerpt{
				App:      app,
				Path:     "journal://" + unit,
				Line:     clampLine(stripANSI(line), 240),
				Severity: detectSeverity(line),
			})
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// formatLogExcerptHint condenses the first excerpt into a single narrative
// line suitable for the top of the RCA evidence list. Returns "" when
// nothing interesting showed up.
func formatLogExcerptHint(excerpts []model.LogExcerpt) string {
	if len(excerpts) == 0 {
		return ""
	}
	e := excerpts[0]
	src := shortPath(e.Path)
	tag := e.Severity
	if tag == "" {
		tag = "LOG"
	}
	suffix := ""
	if len(excerpts) > 1 {
		suffix = " (+" + itoa(len(excerpts)-1) + " more)"
	}
	return tag + " from " + e.App + " @ " + src + ": " + clampLine(e.Line, 160) + suffix
}

// shortPath trims leading directories so log references stay readable in the
// narrow RCA evidence list. journal:// URLs pass through unchanged.
func shortPath(p string) string {
	if strings.HasPrefix(p, "journal://") {
		return p
	}
	// Keep the last two path components for context (e.g. "mysql/error.log").
	parts := strings.Split(p, string(os.PathSeparator))
	if len(parts) <= 2 {
		return p
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}

// ── small helpers ────────────────────────────────────────────────────────────

// ansiEscape matches CSI/OSC ANSI color escape sequences so a stray control
// sequence in a log line doesn't corrupt our ANSI TUI output.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func stripANSI(s string) string { return ansiEscape.ReplaceAllString(s, "") }

func clampLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// detectSeverity returns a short tag derived from the line content — used
// purely for display coloring; matching happens via the regex above.
var sevPatterns = []struct {
	tag string
	re  *regexp.Regexp
}{
	{"FATAL", regexp.MustCompile(`(?i)\b(fatal|panic|emerg)\b`)},
	{"OOM", regexp.MustCompile(`(?i)\b(oom|out of memory|cannot allocate)\b`)},
	{"ERROR", regexp.MustCompile(`(?i)\b(error|crit|aborted)\b`)},
	{"SLOW", regexp.MustCompile(`(?i)\b(slow query|slow log|timed out|timeout)\b`)},
	{"WARN", regexp.MustCompile(`(?i)\b(warn|warning|alert)\b`)},
}

func detectSeverity(line string) string {
	for _, p := range sevPatterns {
		if p.re.MatchString(line) {
			return p.tag
		}
	}
	return ""
}
