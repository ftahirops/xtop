//go:build linux

package phpfpm

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ftahirops/xtop/model"
)

var (
	skipDeepProbes atomic.Bool
	// forceRefresh is flipped to true by the TUI when the user presses
	// D / R / etc. The next Collect() call after that does a full
	// refresh instead of returning the cached snapshot.
	forceRefresh atomic.Bool
	// forceDeepScanSite, when non-empty, asks the next refresh to also
	// re-run the docroot filesystem scan (normally cached for 10 min).
	// Empty string means "no deep scan"; "*" means "all sites".
	forceDeepScanSite atomic.Value
	// refreshInterval is how often we actually do the FastCGI status
	// fetch / access-log tail / slow-log tail. Default 30s — the engine
	// ticks faster than that (every 2-3s in TUI mode) but PHP-FPM data
	// is cheap to display and expensive to fetch, so we throttle.
	refreshInterval = 30 * time.Second
)

func SetSkipDeepProbes(v bool) { skipDeepProbes.Store(v) }

// TriggerRefresh asks the next Collect() to do a full refresh instead
// of returning the cached snapshot. Called from the TUI when the user
// presses R.
func TriggerRefresh() { forceRefresh.Store(true) }

// TriggerDeepScan asks the next refresh to also re-run the docroot
// filesystem scan. `site` may be a domain name or "*" for all.
func TriggerDeepScan(site string) {
	forceDeepScanSite.Store(site)
	forceRefresh.Store(true)
}

// LastRefreshAt is exposed so the TUI can show how stale the data is.
func (c *Collector) LastRefreshAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRefreshAt
}

// RefreshPending returns true if a force-refresh has been queued but
// the collector hasn't processed it yet.
func RefreshPending() bool { return forceRefresh.Load() }

// DeepScanPending returns the site target queued for fsscan, or "" if
// no deep-scan is queued.
func DeepScanPending() string {
	v, _ := forceDeepScanSite.Load().(string)
	return v
}

// Stats are package-level holders we update from Collect so the TUI
// can show "last refresh: 12s ago" without needing the Collector ptr.
var (
	statsMu       sync.Mutex
	lastRefreshAt time.Time
	lastRefreshMs int
)

// LastRefreshStats returns the time of the most recent refresh and how
// long it took (rough). Used by the TUI for the header banner.
func LastRefreshStats() (time.Time, int) {
	statsMu.Lock()
	defer statsMu.Unlock()
	return lastRefreshAt, lastRefreshMs
}

type Collector struct {
	mu              sync.Mutex
	cachedMasters   []discovered
	cachedVhosts    []vhostInfo
	mastersCachedAt time.Time
	vhostsCachedAt  time.Time
	cacheTTL        time.Duration

	// Cached result of the last full refresh — returned on hot ticks.
	cachedMetrics model.PHPFPMMetrics
	lastRefreshAt time.Time
}

func NewCollector() *Collector {
	return &Collector{cacheTTL: 15 * time.Second}
}

func (c *Collector) Name() string      { return "phpfpm" }
func (c *Collector) MaxMsPerTick() int { return 2500 }

func (c *Collector) Collect(snap *model.Snapshot) error {
	// Hot-tick path: if we have cached data and the refresh interval
	// hasn't elapsed and the user hasn't forced a refresh, just return
	// the cached snapshot. This keeps the F8 page lively without
	// hammering FastCGI + the access logs every 3s.
	c.mu.Lock()
	if !c.lastRefreshAt.IsZero() &&
		time.Since(c.lastRefreshAt) < refreshInterval &&
		!forceRefresh.Load() {
		snap.Global.PHPFPM = c.cachedMetrics
		c.mu.Unlock()
		return nil
	}
	// Consume the force-refresh flag.
	forceRefresh.Store(false)
	c.mu.Unlock()

	// Honor a one-shot deep-scan request: invalidate fsScanCache for
	// the requested site (or all sites) so this refresh re-walks.
	if site, ok := forceDeepScanSite.Load().(string); ok && site != "" {
		invalidateFSCache(site)
		forceDeepScanSite.Store("")
	}

	startedAt := time.Now()
	defer func() {
		c.mu.Lock()
		c.cachedMetrics = snap.Global.PHPFPM
		c.lastRefreshAt = time.Now()
		c.mu.Unlock()
		statsMu.Lock()
		lastRefreshAt = time.Now()
		lastRefreshMs = int(time.Since(startedAt).Milliseconds())
		statsMu.Unlock()
	}()

	// 1. Cached discovery — masters + vhosts.
	c.mu.Lock()
	ttl := c.cacheTTL
	vhostTTL := 60 * time.Second
	if skipDeepProbes.Load() {
		ttl = 60 * time.Second
		vhostTTL = 5 * time.Minute
	}
	if time.Since(c.mastersCachedAt) >= ttl || len(c.cachedMasters) == 0 {
		c.cachedMasters = discoverMasters()
		c.mastersCachedAt = time.Now()
	}
	if time.Since(c.vhostsCachedAt) >= vhostTTL || len(c.cachedVhosts) == 0 {
		c.cachedVhosts = discoverVhosts()
		c.vhostsCachedAt = time.Now()
	}
	masters := append([]discovered(nil), c.cachedMasters...)
	vhosts := append([]vhostInfo(nil), c.cachedVhosts...)
	c.mu.Unlock()

	if len(masters) == 0 && len(vhosts) == 0 {
		return nil
	}

	var (
		outMasters []model.PHPFPMMaster
		outWorkers []model.PHPFPMWorker
		masterCaps = map[string]int{} // phpVersion → max_children (approx via WorkerCount for now)
	)

	for _, d := range masters {
		m := model.PHPFPMMaster{
			PID:        d.pid,
			PHPVersion: d.phpVersion,
			ConfigPath: d.configPath,
			ListenAddr: d.listenAddr,
			StatusPath: d.statusPath,
			PoolName:   d.poolName,
		}
		workerPIDs := findWorkers(d.pid)
		m.WorkerCount = len(workerPIDs)
		masterCaps[d.phpVersion] = len(workerPIDs)

		// FastCGI status fetch is cheap (~2 ms per pool) — run it
		// regardless of Guardian level. Only the heavier log tails and
		// docroot scan respect skipDeepProbes below.
		if d.listenAddr != "" && d.statusPath != "" {
			body, err := fcgiQuery(d.listenAddr, d.statusPath, "full", 1500*time.Millisecond)
			if err != nil {
				m.StatusOK = false
				m.StatusError = err.Error()
			} else {
				m.StatusOK = true
				pool, workers := parseStatusFull(body, d.pid, d.phpVersion)
				if pool != "" {
					m.PoolName = pool
				}
				outWorkers = append(outWorkers, workers...)
			}
		} else if d.listenAddr == "" {
			m.StatusError = "no listen address parsed from config"
		} else {
			m.StatusError = "no pm.status_path configured"
		}
		outMasters = append(outMasters, m)
	}

	// 2. Live /proc joins — CPU%, RSS, disk I/O.
	joinLiveProcStats(outWorkers)
	joinLiveIO(outWorkers)

	// 3. Filter out workers that just served the status endpoint —
	// they pollute App attribution because the script is empty.
	cleanWorkers := outWorkers[:0]
	for _, w := range outWorkers {
		if w.RequestURI != "" && containsStatusPath(w.RequestURI) {
			continue
		}
		cleanWorkers = append(cleanWorkers, w)
	}
	outWorkers = cleanWorkers

	// 4. Tail access + slow logs. Incremental — cheap once seeded
	// (only reads bytes appended since last tick). Run regardless of
	// Guardian level; the fsscan inside the aggregator is the heavy
	// step and *that* one still respects guardLevel.
	accLogs := tailAccessLogs(vhosts)
	slow := tailSlowLogs()

	// 5. Per-app rollup with all signals folded in + RCA evaluation.
	apps := rollupApps(outWorkers, vhosts, accLogs, slow, masterCaps)

	snap.Global.PHPFPM = model.PHPFPMMetrics{
		Masters: outMasters,
		Workers: outWorkers,
		Apps:    apps,
	}
	return nil
}

// containsStatusPath returns true if a request URI is one of the
// /phpfpm_*_status endpoints we ourselves are querying.
func containsStatusPath(uri string) bool {
	if uri == "" {
		return false
	}
	for _, prefix := range []string{
		"/phpfpm_", "/phpfpm-",
	} {
		if len(uri) >= len(prefix) && uri[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
