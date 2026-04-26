package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ConfigDriftDetector watches a curated set of high-impact config files and
// reports when any of them change. Drift events feed into the existing
// "Recent Activity" stream on the overview page, and — more importantly —
// the RCA narrative, so when an incident starts 8 minutes after a change to
// /etc/nginx/nginx.conf, the operator sees that immediately.
//
// Design constraints:
//   - Cheap: stat() on ~60 files every 30s, SHA256 only when mtime moves.
//   - Resilient: missing files are fine; absence→presence counts as added,
//     presence→absence as removed, hash change as modified.
//   - Persistent: the baseline is saved to ~/.xtop/config-baseline.json so a
//     restart doesn't re-flood "modified" events.
//   - Bounded scope: NOT a general-purpose file watcher — only the explicit
//     watchlist below (editable via $XTOP_CONFIG_WATCH).
type ConfigDriftDetector struct {
	mu         sync.Mutex
	baseline   map[string]fileFingerprint // path → last known state
	baselinePath string
	lastScan   time.Time
	scanEvery  time.Duration
	recent     []model.SystemChange // drift events from the last scan, kept for lookback
	recentTTL  time.Duration
	patterns   []string             // explicit paths + glob prefixes
}

type fileFingerprint struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mtime"`
	Hash    string    `json:"hash"`    // sha256 hex; "" when the file is absent
	Exists  bool      `json:"exists"`
}

// configWatchlist is the set of paths xtop monitors. Entries may be explicit
// files or directory prefixes — anything under a directory prefix is walked
// one level deep for *.conf / *.cnf / *.yml / *.yaml / *.service / *.timer.
//
// We bias toward "operational" files — what an SRE actually edits when they
// break things — rather than everything in /etc.
var configWatchlist = []string{
	// Kernel / resource tuning
	"/etc/sysctl.conf",
	"/etc/sysctl.d/",
	"/etc/security/limits.conf",
	"/etc/security/limits.d/",
	"/etc/systemd/system.conf",
	"/etc/systemd/journald.conf",
	"/etc/systemd/resolved.conf",

	// Mounts and boot-time
	"/etc/fstab",
	"/etc/default/grub",

	// Systemd units
	"/etc/systemd/system/",

	// Scheduled jobs
	"/etc/crontab",
	"/etc/cron.d/",
	"/etc/anacrontab",

	// Common server apps
	"/etc/nginx/nginx.conf",
	"/etc/nginx/sites-enabled/",
	"/etc/nginx/conf.d/",
	"/etc/apache2/apache2.conf",
	"/etc/apache2/sites-enabled/",
	"/etc/httpd/conf/httpd.conf",
	"/etc/mysql/my.cnf",
	"/etc/mysql/mysql.conf.d/",
	"/etc/mysql/mariadb.conf.d/",
	"/etc/postgresql/",           // walked; picks up postgresql.conf, pg_hba.conf
	"/etc/redis/redis.conf",
	"/etc/memcached.conf",
	"/etc/elasticsearch/elasticsearch.yml",
	"/etc/logstash/logstash.yml",
	"/etc/kibana/kibana.yml",
	"/etc/rabbitmq/rabbitmq.conf",
	"/etc/docker/daemon.json",
	"/etc/containerd/config.toml",
	"/etc/haproxy/haproxy.cfg",
	"/etc/traefik/traefik.yml",

	// Network
	"/etc/hosts",
	"/etc/resolv.conf",
	"/etc/netplan/",
	"/etc/network/interfaces",
}

// NewConfigDriftDetector creates a detector with the default watchlist.
func NewConfigDriftDetector() *ConfigDriftDetector {
	home, _ := os.UserHomeDir()
	baselinePath := filepath.Join(home, ".xtop", "config-baseline.json")
	_ = os.MkdirAll(filepath.Dir(baselinePath), 0o755)

	d := &ConfigDriftDetector{
		baseline:     make(map[string]fileFingerprint),
		baselinePath: baselinePath,
		scanEvery:    30 * time.Second,
		recentTTL:    6 * time.Hour,
		patterns:     configWatchlist,
	}
	// Allow ops to extend the watchlist via $XTOP_CONFIG_WATCH (':'-separated).
	if extra := os.Getenv("XTOP_CONFIG_WATCH"); extra != "" {
		for _, p := range strings.Split(extra, ":") {
			if p = strings.TrimSpace(p); p != "" {
				d.patterns = append(d.patterns, p)
			}
		}
	}
	d.loadBaseline()
	return d
}

// Tick runs a detection pass if scanEvery has elapsed since the last scan.
// Returns any newly-detected drift events (added / modified / removed). The
// detector also keeps a 6-hour buffer of events for RCA correlation — see
// RecentWithin.
func (d *ConfigDriftDetector) Tick() []model.SystemChange {
	d.mu.Lock()
	defer d.mu.Unlock()

	if time.Since(d.lastScan) < d.scanEvery {
		return nil
	}
	d.lastScan = time.Now()

	newChanges := d.scan()
	if len(newChanges) > 0 {
		d.recent = append(d.recent, newChanges...)
		d.trimRecent()
	}
	// Persist the baseline regardless of whether this scan emitted events —
	// otherwise the first-run baseline (which emits nothing by design) would
	// never hit disk, and every restart would re-prime from zero.
	_ = d.persistBaselineLocked()
	return newChanges
}

// RecentWithin returns drift events that happened within `window` of `ref`.
// Used by RCA to correlate a config change with an incident that started
// shortly after.
func (d *ConfigDriftDetector) RecentWithin(ref time.Time, window time.Duration) []model.SystemChange {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []model.SystemChange
	lo := ref.Add(-window)
	for _, c := range d.recent {
		if (c.When.Equal(lo) || c.When.After(lo)) && c.When.Before(ref.Add(window)) {
			out = append(out, c)
		}
	}
	return out
}

// ── Internals ────────────────────────────────────────────────────────────────

func (d *ConfigDriftDetector) trimRecent() {
	cutoff := time.Now().Add(-d.recentTTL)
	kept := d.recent[:0]
	for _, c := range d.recent {
		if c.When.After(cutoff) {
			kept = append(kept, c)
		}
	}
	d.recent = kept
}

// scan walks the watchlist, compares to the baseline, and emits drift events.
// Must be called with the lock held.
func (d *ConfigDriftDetector) scan() []model.SystemChange {
	seen := make(map[string]bool)
	var changes []model.SystemChange

	for _, pat := range d.patterns {
		paths := expandPath(pat)
		for _, p := range paths {
			seen[p] = true
			fp := fingerprint(p)

			prev, had := d.baseline[p]
			switch {
			case !had && fp.Exists:
				// First time we've seen this file. On fresh install, treat as baseline
				// silently — avoid flooding the operator with "added" events on day one.
				// We only emit "added" when the detector has prior state for OTHER
				// files (i.e. the baseline was loaded from disk).
				if len(d.baseline) > 0 {
					changes = append(changes, model.SystemChange{
						Type:   "config_added",
						Detail: p,
						When:   fp.ModTime,
					})
				}
				d.baseline[p] = fp
			case had && !fp.Exists && prev.Exists:
				changes = append(changes, model.SystemChange{
					Type:   "config_removed",
					Detail: p,
					When:   time.Now(),
				})
				d.baseline[p] = fp
			case had && fp.Exists && (fp.Hash != prev.Hash || fp.Size != prev.Size):
				changes = append(changes, model.SystemChange{
					Type:   "config_modified",
					Detail: p,
					When:   fp.ModTime,
				})
				d.baseline[p] = fp
			case !had && !fp.Exists:
				// Not on this system — record absence so we notice additions later.
				d.baseline[p] = fp
			}
		}
	}

	// Files that WERE in the baseline but are not in the current watchlist
	// anymore (e.g. operator pruned XTOP_CONFIG_WATCH) — we just leave them;
	// no false positives, no noise.
	_ = seen
	return changes
}

func fingerprint(path string) fileFingerprint {
	info, err := os.Stat(path)
	if err != nil {
		return fileFingerprint{Path: path, Exists: false}
	}
	if info.IsDir() {
		// Guard: callers should only pass files here.
		return fileFingerprint{Path: path, Exists: false}
	}
	fp := fileFingerprint{
		Path:    path,
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Exists:  true,
	}
	// Cap hashed size at 2 MiB — anything bigger is almost certainly a log or
	// state file we shouldn't be fingerprinting anyway.
	if info.Size() > 2<<20 {
		fp.Hash = "oversized"
		return fp
	}
	f, err := os.Open(path)
	if err != nil {
		fp.Hash = "unreadable"
		return fp
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fp.Hash = "unreadable"
		return fp
	}
	fp.Hash = hex.EncodeToString(h.Sum(nil))
	return fp
}

// expandPath returns the set of files to fingerprint for a pattern entry.
// Entries are either:
//   - explicit files → returned as-is (even if absent)
//   - directories (ending in /) → walked one level; file extensions filtered.
func expandPath(pat string) []string {
	if !strings.HasSuffix(pat, "/") {
		return []string{pat}
	}
	entries, err := os.ReadDir(pat)
	if err != nil {
		return []string{pat + ".dir-absent"} // sentinel; fingerprint will return Exists=false
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			// One more level — common for /etc/postgresql/<ver>/main/
			sub := filepath.Join(pat, e.Name())
			if entries2, err := os.ReadDir(sub); err == nil {
				for _, e2 := range entries2 {
					if !e2.IsDir() && isConfigExt(e2.Name()) {
						out = append(out, filepath.Join(sub, e2.Name()))
					}
				}
			}
			continue
		}
		if isConfigExt(e.Name()) {
			out = append(out, filepath.Join(pat, e.Name()))
		}
	}
	return out
}

func isConfigExt(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".conf", ".cnf", ".cfg", ".yml", ".yaml", ".json", ".toml",
		".service", ".timer", ".mount", ".socket", ".target",
		".ini", ".properties":
		return true
	}
	// Files without an extension are skipped from directory walks — the
	// explicit per-file entries above still catch things like /etc/crontab
	// and /etc/fstab.
	return false
}

// formatConfigDriftHint turns a list of recent drift events into a single
// narrative-evidence line. The exact shape:
//
//	CONFIG CHANGED 8m before degradation: /etc/nginx/nginx.conf (+1 more)
//
// Filters out xtop's own state files (the detector itself may trigger writes
// under ~/.xtop). Returns "" if the filtered list is empty.
func formatConfigDriftHint(events []model.SystemChange) string {
	// Dedupe while tracking the newest timestamp per path.
	type entry struct {
		path string
		when time.Time
	}
	byPath := make(map[string]entry)
	for _, e := range events {
		if e.Detail == "" || strings.Contains(e.Detail, "/.xtop/") {
			continue
		}
		existing, ok := byPath[e.Detail]
		if !ok || e.When.After(existing.when) {
			byPath[e.Detail] = entry{path: e.Detail, when: e.When}
		}
	}
	if len(byPath) == 0 {
		return ""
	}
	// Pick the most recent entry as the headline; surround files go in the
	// "+N more" tail. Newest is the most actionable because it's closest to
	// the incident start time.
	var headline entry
	for _, e := range byPath {
		if headline.when.IsZero() || e.when.After(headline.when) {
			headline = e
		}
	}
	ageLabel := fmtDriftAge(time.Since(headline.when))
	if len(byPath) == 1 {
		return "CONFIG CHANGED " + ageLabel + " before degradation: " + headline.path
	}
	return "CONFIG CHANGED " + ageLabel + " before degradation: " + headline.path +
		" (+" + itoa(len(byPath)-1) + " more)"
}

func fmtDriftAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m"
	default:
		return itoa(int(d.Hours())) + "h"
	}
}

// itoa avoids importing strconv just for one call inside formatConfigDriftHint.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ── Baseline persistence ─────────────────────────────────────────────────────

func (d *ConfigDriftDetector) loadBaseline() {
	f, err := os.Open(d.baselinePath)
	if err != nil {
		return
	}
	defer f.Close()
	var m map[string]fileFingerprint
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return
	}
	d.baseline = m
}

func (d *ConfigDriftDetector) persistBaselineLocked() error {
	tmp := d.baselinePath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d.baseline); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, d.baselinePath)
}
