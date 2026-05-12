//go:build linux

package phpfpm

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ftahirops/xtop/model"
)

var (
	skipDeepProbes atomic.Bool
	// forceRefresh is flipped to true by the TUI when the user presses
	// R / D / etc. The next Collect() call after that does a full
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

// TriggerRefresh asks the next Collect() to do a full refresh.
func TriggerRefresh() { forceRefresh.Store(true) }

// TriggerDeepScan asks the next refresh to also re-walk the docroot
// filesystem scan for one site (or "*" for all).
func TriggerDeepScan(site string) {
	forceDeepScanSite.Store(site)
	forceRefresh.Store(true)
}

func (c *Collector) LastRefreshAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRefreshAt
}

func RefreshPending() bool { return forceRefresh.Load() }

func DeepScanPending() string {
	v, _ := forceDeepScanSite.Load().(string)
	return v
}

var (
	statsMu       sync.Mutex
	lastRefreshAt time.Time
	lastRefreshMs int
)

func LastRefreshStats() (time.Time, int) {
	statsMu.Lock()
	defer statsMu.Unlock()
	return lastRefreshAt, lastRefreshMs
}

type Collector struct {
	mu              sync.Mutex
	cachedMasters   []discoveredMaster
	cachedVhosts    []vhostInfo
	mastersCachedAt time.Time
	vhostsCachedAt  time.Time
	cacheTTL        time.Duration

	cachedMetrics model.PHPFPMMetrics
	lastRefreshAt time.Time
}

func NewCollector() *Collector {
	return &Collector{cacheTTL: 15 * time.Second}
}

func (c *Collector) Name() string      { return "phpfpm" }
func (c *Collector) MaxMsPerTick() int { return 2500 }

func (c *Collector) Collect(snap *model.Snapshot) error {
	// Hot-tick path: serve cached if recent + not forced.
	c.mu.Lock()
	if !c.lastRefreshAt.IsZero() &&
		time.Since(c.lastRefreshAt) < refreshInterval &&
		!forceRefresh.Load() {
		snap.Global.PHPFPM = c.cachedMetrics
		c.mu.Unlock()
		return nil
	}
	forceRefresh.Store(false)
	c.mu.Unlock()

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

	// 1. Discovery (cached).
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
	masters := append([]discoveredMaster(nil), c.cachedMasters...)
	vhosts := append([]vhostInfo(nil), c.cachedVhosts...)
	c.mu.Unlock()

	if len(masters) == 0 && len(vhosts) == 0 {
		return nil
	}

	var (
		outMasters []model.PHPFPMMaster
		outWorkers []model.PHPFPMWorker
		masterCaps = map[string]int{}
	)

	for _, dm := range masters {
		// If a master has no pools we still surface it as a row so the
		// operator sees the master exists. With pools we emit one row
		// per pool — each pool is effectively a "mini-master" from the
		// operator's POV.
		if len(dm.pools) == 0 {
			m := model.PHPFPMMaster{
				PID:         dm.pid,
				PHPVersion:  dm.phpVersion,
				ConfigPath:  dm.configPath,
				WorkerCount: len(findAllWorkersForMaster(dm.pid)),
				StatusError: "no pools parsed from config",
			}
			outMasters = append(outMasters, m)
			masterCaps[dm.phpVersion] = m.WorkerCount
			continue
		}

		totalWorkers := 0
		for _, pool := range dm.pools {
			workerPIDs := findWorkersForPool(dm.pid, pool.name)
			totalWorkers += len(workerPIDs)

			m := model.PHPFPMMaster{
				PID:         dm.pid,
				PHPVersion:  dm.phpVersion,
				ConfigPath:  dm.configPath,
				ListenAddr:  pool.listen,
				StatusPath:  pool.statusPath,
				PoolName:    pool.name,
				WorkerCount: len(workerPIDs),
			}
			// Fetch FastCGI status for this pool, if it has a status_path.
			switch {
			case pool.listen == "":
				m.State = "no-socket"
				m.StatusError = "could not resolve listen address from config"
			case pool.statusPath == "":
				// Common on Plesk + many manual setups. Not an error —
				// the pool is fine, we just can't introspect requests.
				m.State = "no-status"
				m.StatusError = "pm.status_path not configured"
			default:
				body, err := fcgiQuery(pool.listen, pool.statusPath, "full", 1500*time.Millisecond)
				if err != nil {
					m.StatusOK = false
					m.State = "connect-failed"
					m.StatusError = err.Error()
				} else {
					m.StatusOK = true
					m.State = "ok"
					_, workers := parseStatusFull(body, dm.pid, dm.phpVersion)
					for i := range workers {
						if workers[i].PoolName == "" {
							workers[i].PoolName = pool.name
						}
					}
					outWorkers = append(outWorkers, workers...)
				}
			}
			outMasters = append(outMasters, m)
		}
		masterCaps[dm.phpVersion] += totalWorkers
	}

	// Live /proc joins.
	joinLiveProcStats(outWorkers)
	joinLiveIO(outWorkers)

	// Filter workers that just served the status endpoint (would
	// pollute App attribution).
	cleanWorkers := outWorkers[:0]
	for _, w := range outWorkers {
		if w.RequestURI != "" && containsStatusPath(w.RequestURI) {
			continue
		}
		cleanWorkers = append(cleanWorkers, w)
	}
	outWorkers = cleanWorkers

	// Tail logs (always — cheap once seeded).
	accLogs := tailAccessLogs(vhosts)
	slow := tailSlowLogs()

	apps := rollupApps(outWorkers, vhosts, accLogs, slow, masterCaps, outMasters)

	snap.Global.PHPFPM = model.PHPFPMMetrics{
		Masters: outMasters,
		Workers: outWorkers,
		Apps:    apps,
	}
	return nil
}

func containsStatusPath(uri string) bool {
	if uri == "" {
		return false
	}
	for _, prefix := range []string{"/phpfpm_", "/phpfpm-", "/fpm-status", "/php-fpm-status", "/status"} {
		if strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}
