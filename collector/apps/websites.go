//go:build linux

package apps

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// websiteCollector gathers per-website metrics from PHP-FPM pools, logs, and databases.
// It is shared across Plesk, Nginx, Apache, and PHP-FPM modules.
type websiteCollector struct {
	mu       sync.Mutex
	lastRun  time.Time
	cache    []model.WebsiteMetrics
	diskCache map[string]float64
	lastDisk  time.Time
	dbCache   map[string]float64
	lastDB    time.Time
}

var sharedWebsiteCollector = &websiteCollector{
	diskCache: make(map[string]float64),
	dbCache:   make(map[string]float64),
}

// CollectWebsites returns per-website metrics. Results are cached for 10s.
func CollectWebsites() []model.WebsiteMetrics {
	wc := sharedWebsiteCollector
	wc.mu.Lock()
	defer wc.mu.Unlock()

	if wc.cache != nil && time.Since(wc.lastRun) < 10*time.Second {
		return wc.cache
	}

	sites := wc.collect()
	wc.cache = sites
	wc.lastRun = time.Now()
	return sites
}

func (wc *websiteCollector) collect() []model.WebsiteMetrics {
	// Step 1: Discover PHP-FPM pools across all PHP versions
	pools := wc.discoverPools()

	// Step 2: Map PIDs to pools and gather CPU/RSS
	wc.collectProcessMetrics(pools)

	// Step 3: Hits/min from access logs
	wc.collectHits(pools)

	// Step 4: DB sizes (every 60s)
	if time.Since(wc.lastDB) > 60*time.Second {
		wc.collectDBSizes()
		wc.lastDB = time.Now()
	}

	// Step 5: Disk usage (every 5 min — slow)
	if time.Since(wc.lastDisk) > 5*time.Minute {
		wc.collectDiskUsage(pools)
		wc.lastDisk = time.Now()
	}

	// Build results
	var sites []model.WebsiteMetrics
	for _, p := range pools {
		p.DBSizeMB = wc.dbCache[p.Domain]
		p.DiskMB = wc.diskCache[p.Domain]
		p.Active = p.CPUPct > 0.01 || p.Workers > 0
		sites = append(sites, *p.WebsiteMetrics)
	}

	return sites
}

type poolInfo struct {
	*model.WebsiteMetrics
	masterPID int
	poolName  string
	sockPath  string
	confPath  string
}

func (wc *websiteCollector) discoverPools() map[string]*poolInfo {
	pools := make(map[string]*poolInfo)

	// Scan Plesk PHP-FPM pool configs
	for _, ver := range []string{"8.1", "8.2", "8.3", "8.4"} {
		poolDir := fmt.Sprintf("/opt/plesk/php/%s/etc/php-fpm.d/", ver)
		files, err := filepath.Glob(poolDir + "*.conf")
		if err != nil {
			continue
		}
		for _, confPath := range files {
			domain := strings.TrimSuffix(filepath.Base(confPath), ".conf")
			// Skip plesk internal pools
			if domain == "plesk-service.localdomain" || domain == "www" {
				continue
			}

			maxChildren := 0
			f, err := os.Open(confPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "pm.max_children") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						maxChildren, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
					}
				}
			}
			f.Close()

			phpVer := ver
			if _, exists := pools[domain]; exists {
				// Already found in another PHP version — higher version wins
				continue
			}
			pools[domain] = &poolInfo{
				WebsiteMetrics: &model.WebsiteMetrics{
					Domain:     domain,
					MaxWorkers: maxChildren,
					PHPVersion: phpVer,
				},
				poolName: domain,
				confPath: confPath,
			}
		}
	}

	// Also scan system PHP-FPM pools (/etc/php/*/fpm/pool.d/)
	sysFiles, _ := filepath.Glob("/etc/php/*/fpm/pool.d/*.conf")
	for _, confPath := range sysFiles {
		domain := strings.TrimSuffix(filepath.Base(confPath), ".conf")
		if domain == "www" || pools[domain] != nil {
			continue
		}
		// Extract PHP version from path
		parts := strings.Split(confPath, "/")
		phpVer := ""
		for _, p := range parts {
			if len(p) > 0 && p[0] >= '0' && p[0] <= '9' {
				phpVer = p
				break
			}
		}
		pools[domain] = &poolInfo{
			WebsiteMetrics: &model.WebsiteMetrics{
				Domain:     domain,
				PHPVersion: phpVer,
			},
			poolName: domain,
			confPath: confPath,
		}
	}

	return pools
}

func (wc *websiteCollector) collectProcessMetrics(pools map[string]*poolInfo) {
	pids, _ := procEntries()
	for _, pid := range pids {
		_, comm := readPPIDComm(pid)
		if !strings.HasPrefix(comm, "php-fpm") && comm != "php-fpm8.3" && comm != "php-fpm8.4" {
			continue
		}
		// Read cmdline to find pool name: "php-fpm: pool <domain>"
		cmdline := readProcCmdline(pid)
		if !strings.Contains(cmdline, "pool ") {
			continue
		}

		idx := strings.Index(cmdline, "pool ")
		if idx < 0 {
			continue
		}
		poolName := strings.TrimSpace(cmdline[idx+5:])
		// Remove trailing null bytes or spaces
		poolName = strings.TrimRight(poolName, "\x00 ")

		pool, ok := pools[poolName]
		if !ok {
			continue
		}

		// This is a worker process for this pool
		pool.Workers++
		pool.RSSMB += readProcRSS(pid)
		pool.CPUPct += readProcCPUPct(pid, readProcUptime(pid))
	}
}

func (wc *websiteCollector) collectHits(pools map[string]*poolInfo) {
	now := time.Now()
	cutoff := now.Add(-60 * time.Second)

	for domain, pool := range pools {
		// Try various log paths
		logPaths := []string{
			fmt.Sprintf("/var/www/vhosts/%s/logs/proxy_access_ssl_log", domain),
			fmt.Sprintf("/var/www/vhosts/%s/logs/access_ssl_log", domain),
			fmt.Sprintf("/var/www/vhosts/%s/logs/proxy_access_log", domain),
			fmt.Sprintf("/var/www/vhosts/%s/logs/access_log", domain),
		}

		for _, logPath := range logPaths {
			hits := countRecentHits(logPath, cutoff)
			if hits > 0 {
				pool.HitsPerMin = hits
				break
			}
		}
	}
}

// countRecentHits counts log lines from the last 60 seconds.
// Reads from the end of file for efficiency.
func countRecentHits(path string, cutoff time.Time) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	// Seek to last 256KB — enough for ~60s of typical traffic
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	offset := info.Size() - 256*1024
	if offset < 0 {
		offset = 0
	}
	f.Seek(offset, 0)

	count := 0
	scanner := bufio.NewScanner(f)
	// Increase buffer for long lines
	buf := make([]byte, 0, 8192)
	scanner.Buffer(buf, 16384)

	for scanner.Scan() {
		line := scanner.Text()
		// Parse timestamp: [15/Mar/2026:19:54:18 +0000]
		ts := extractLogTimestamp(line)
		if ts.IsZero() {
			continue
		}
		if ts.After(cutoff) {
			count++
		}
	}
	return count
}

// extractLogTimestamp extracts timestamp from combined/common log format.
func extractLogTimestamp(line string) time.Time {
	start := strings.Index(line, "[")
	if start < 0 {
		return time.Time{}
	}
	end := strings.Index(line[start:], "]")
	if end < 0 {
		return time.Time{}
	}
	tsStr := line[start+1 : start+end]
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", tsStr)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (wc *websiteCollector) collectDBSizes() {
	// Query Plesk database for per-domain DB sizes
	out, err := exec.Command("plesk", "db", "-Ne",
		`SELECT d.name, ROUND(SUM(IFNULL(
			(SELECT SUM(data_length + index_length) / 1048576
			 FROM information_schema.tables
			 WHERE table_schema = db.name), 0)), 1)
		 FROM data_bases db
		 JOIN domains d ON db.dom_id = d.id
		 GROUP BY d.name`).Output()
	if err != nil {
		return
	}

	wc.dbCache = make(map[string]float64)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			size, _ := strconv.ParseFloat(fields[1], 64)
			wc.dbCache[fields[0]] = size
		}
	}
}

func (wc *websiteCollector) collectDiskUsage(pools map[string]*poolInfo) {
	wc.diskCache = make(map[string]float64)
	for domain := range pools {
		vhostDir := fmt.Sprintf("/var/www/vhosts/%s", domain)
		if _, err := os.Stat(vhostDir); err != nil {
			continue
		}
		out, err := exec.Command("du", "-sm", vhostDir).Output()
		if err != nil {
			continue
		}
		fields := strings.Fields(string(out))
		if len(fields) >= 1 {
			mb, _ := strconv.ParseFloat(fields[0], 64)
			wc.diskCache[domain] = mb
		}
	}
}
