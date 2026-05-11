//go:build linux

package phpfpm

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// docrootExists returns true if the path exists and is a directory.
func docrootExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

type procCPUSample struct {
	jiffies uint64
	at      time.Time
}

var (
	cpuSamplesMu sync.Mutex
	cpuSamples   = map[int]procCPUSample{}
	clockTicks   = uint64(100)
)

func joinLiveProcStats(workers []model.PHPFPMWorker) {
	now := time.Now()
	cpuSamplesMu.Lock()
	defer cpuSamplesMu.Unlock()

	live := map[int]struct{}{}
	for i := range workers {
		pid := workers[i].PID
		live[pid] = struct{}{}
		ut, st, rss := readProcStatMin(pid)
		if ut == 0 && st == 0 && rss == 0 {
			continue
		}
		workers[i].LiveRSSKB = int64(rss) * pageSizeKB()
		total := ut + st
		if prev, ok := cpuSamples[pid]; ok {
			elapsed := now.Sub(prev.at).Seconds()
			if elapsed > 0 && total >= prev.jiffies {
				deltaJiffies := float64(total - prev.jiffies)
				pct := (deltaJiffies / float64(clockTicks)) / elapsed * 100.0
				workers[i].LiveCPUPct = pct
			}
		}
		cpuSamples[pid] = procCPUSample{jiffies: total, at: now}
	}
	for pid := range cpuSamples {
		if _, ok := live[pid]; !ok {
			delete(cpuSamples, pid)
		}
	}
}

func readProcStatMin(pid int) (utime, stime, rss uint64) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, 0
	}
	s := string(b)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+2 >= len(s) {
		return 0, 0, 0
	}
	fields := strings.Fields(s[rp+2:])
	if len(fields) < 22 {
		return 0, 0, 0
	}
	utime, _ = strconv.ParseUint(fields[11], 10, 64)
	stime, _ = strconv.ParseUint(fields[12], 10, 64)
	rss, _ = strconv.ParseUint(fields[21], 10, 64)
	return utime, stime, rss
}

var pageSizeKBOnce sync.Once
var pageSizeKBCache int64 = 4

func pageSizeKB() int64 {
	pageSizeKBOnce.Do(func() {
		pageSizeKBCache = int64(os.Getpagesize()) / 1024
		if pageSizeKBCache == 0 {
			pageSizeKBCache = 4
		}
	})
	return pageSizeKBCache
}

// rollupApps groups workers by app and folds in access-log + slow-log
// data. Sites with no live workers but with access-log activity are
// still emitted so the user sees the full picture.
func rollupApps(
	workers []model.PHPFPMWorker,
	vhosts []vhostInfo,
	accLogs map[string]accessLogAgg,
	slow map[string]*slowSiteAgg,
	masterCaps map[string]int,
) []model.PHPFPMApp {
	type bucket struct {
		app       model.PHPFPMApp
		uriHits   map[string]int
		scriptHits map[string]int
	}
	m := map[string]*bucket{}

	// Seed buckets from vhosts so every configured site appears.
	for _, v := range vhosts {
		if v.Domain == "" {
			continue
		}
		m[v.Domain] = &bucket{
			app: model.PHPFPMApp{
				App:       v.Domain,
				DocRoot:   v.DocRoot,
				AccessLog: v.AccessLog,
			},
			uriHits:    map[string]int{},
			scriptHits: map[string]int{},
		}
	}

	for _, w := range workers {
		name := w.App
		if name == "" {
			// Skip workers we couldn't attribute (e.g. those that only
			// served the status endpoint). They distort the view.
			continue
		}
		b, ok := m[name]
		if !ok {
			b = &bucket{
				app:        model.PHPFPMApp{App: name, PHPVersion: w.PHPVersion},
				uriHits:    map[string]int{},
				scriptHits: map[string]int{},
			}
			m[name] = b
		}
		b.app.WorkerCount++
		if w.State == "Running" {
			b.app.RunningCount++
		} else {
			b.app.IdleCount++
		}
		b.app.CPUPct += w.LiveCPUPct
		b.app.RSSKB += w.LiveRSSKB
		b.app.DiskReadBps += w.DiskReadBps
		b.app.DiskWriteBps += w.DiskWriteBps
		b.app.RequestsTotal += w.RequestsTotal
		if w.DurationUs > 0 {
			b.app.AvgDurationMs += float64(w.DurationUs) / 1000.0
		}
		if w.RequestURI != "" {
			b.uriHits[stripQuery(w.RequestURI)]++
		}
		if w.Script != "" {
			b.scriptHits[w.Script]++
		}
		if b.app.PHPVersion == "" || w.PHPVersion > b.app.PHPVersion {
			b.app.PHPVersion = w.PHPVersion
		}
	}

	// Kick off IP enrichment for every IP we're about to display. This
	// is a no-op for already-cached IPs and runs concurrent rDNS for
	// the rest with a 200ms timeout each. Results land in ipCache by
	// the time we call getCachedIP() below.
	{
		all := map[string]struct{}{}
		for _, agg := range accLogs {
			for _, h := range agg.TopIPs {
				all[h.IP] = struct{}{}
			}
		}
		ips := make([]string, 0, len(all))
		for ip := range all {
			ips = append(ips, ip)
		}
		enrichIPs(ips)
	}

	// Fold in access-log aggregates.
	for domain, agg := range accLogs {
		b, ok := m[domain]
		if !ok {
			b = &bucket{
				app:        model.PHPFPMApp{App: domain},
				uriHits:    map[string]int{},
				scriptHits: map[string]int{},
			}
			m[domain] = b
		}
		b.app.AccessReqs = agg.TotalReqs
		b.app.AccessBytes = agg.TotalBytes
		b.app.Status2xx = agg.Status2xx
		b.app.Status3xx = agg.Status3xx
		b.app.Status4xx = agg.Status4xx
		b.app.Status5xx = agg.Status5xx
		for _, h := range agg.TopIPs {
			ei := getCachedIP(h.IP)
			b.app.TopIPs = append(b.app.TopIPs, model.PHPFPMIPHit{
				IP: h.IP, Hits: h.Hits,
				RDNS: ei.RDNS, Provider: ei.Provider, Country: ei.Country,
			})
		}
		for _, h := range agg.TopURIs {
			b.app.TopAccessURIs = append(b.app.TopAccessURIs, model.PHPFPMURIHit{URI: h.URI, Hits: h.Hits})
		}
		for _, p := range agg.IPURIPairs {
			b.app.TopIPURIs = append(b.app.TopIPURIs, model.PHPFPMIPURIHit{IP: p.IP, URI: p.URI, Hits: p.Hits})
		}
	}

	// Fold in slow-log aggregates.
	for domain, sa := range slow {
		b, ok := m[domain]
		if !ok {
			b = &bucket{
				app:        model.PHPFPMApp{App: domain},
				uriHits:    map[string]int{},
				scriptHits: map[string]int{},
			}
			m[domain] = b
		}
		b.app.SlowBlocksTotal = sa.BlocksTotal
		for _, kv := range topN(sa.ScriptHits, 10) {
			b.app.TopSlowScripts = append(b.app.TopSlowScripts, model.PHPFPMScriptHit{Script: kv.K, Hits: kv.V})
		}
		// Classify each blocking PHP call so we can show category +
		// severity + optimization tip later.
		raw := make([]CallFnCount, 0, 10)
		for _, kv := range topN(sa.LastFunctions, 10) {
			raw = append(raw, CallFnCount{Function: kv.K, Hits: kv.V})
		}
		for _, cc := range ClassifyTopCalls(raw) {
			b.app.TopSlowFns = append(b.app.TopSlowFns, model.PHPFPMFunctionHit{
				Function:    cc.Function,
				Hits:        cc.Hits,
				Category:    string(cc.Info.Category),
				Severity:    cc.Info.Severity,
				Explanation: cc.Info.Explanation,
				Optimize:    cc.Info.Optimize,
			})
		}
		for _, s := range sa.Suspicious {
			b.app.WebShellHits = append(b.app.WebShellHits, model.PHPFPMWebShellSuspect{
				Script: s.Script, Function: s.Function, Frame: s.Frame,
			})
		}
	}

	// Finalize each bucket.
	out := make([]model.PHPFPMApp, 0, len(m))
	for _, b := range m {
		// Skip empty seeds (vhost with no workers, no access log activity, no slow events).
		if b.app.WorkerCount == 0 && b.app.AccessReqs == 0 && b.app.SlowBlocksTotal == 0 {
			continue
		}
		if b.app.WorkerCount > 0 {
			b.app.AvgDurationMs /= float64(b.app.WorkerCount)
		}
		// Pick top URI from live workers.
		best, bestN := "", 0
		for u, n := range b.uriHits {
			if n > bestN {
				bestN = n
				best = u
			}
		}
		b.app.TopURI = best
		// TopRunningScripts: from live worker.Script bucket.
		for _, kv := range topN(b.scriptHits, 5) {
			b.app.TopRunningScripts = append(b.app.TopRunningScripts, model.PHPFPMScriptHit{Script: kv.K, Hits: kv.V})
		}
		// Stale-vhost check: configured docroot doesn't exist on disk.
		// Common when a site has been deleted from /www/wwwroot but its
		// nginx config + access log were left behind — attackers still
		// hit it, nginx returns 404 for every request.
		if b.app.DocRoot != "" && !docrootExists(b.app.DocRoot) {
			b.app.DocRootMissing = true
		}

		// Filesystem scan — looks for web shells + binaries in docroot.
		// Cached for 10 min so cost is ~zero on warm runs. Skip only
		// when guard is active AND we have no cached result yet (cold
		// scan can take seconds on large docroots). Also skip when the
		// docroot doesn't exist (nothing to scan).
		if b.app.DocRoot != "" && !b.app.DocRootMissing && !fsScanSkipOnCold(b.app.DocRoot) {
			shells, bins := scanDocroot(b.app.DocRoot)
			for _, f := range shells {
				b.app.FSWebShells = append(b.app.FSWebShells, model.PHPFPMFSFinding{
					Path: f.Path, Kind: f.Kind, Signal: f.Signal,
					Evidence: f.Evidence, Size: f.Size, ModTime: f.ModTime,
				})
			}
			for _, f := range bins {
				b.app.FSBinaries = append(b.app.FSBinaries, model.PHPFPMFSFinding{
					Path: f.Path, Kind: f.Kind, Signal: f.Signal,
					Evidence: f.Evidence, Size: f.Size, ModTime: f.ModTime,
				})
			}
		}
		// Evaluate RCA rules.
		evaluateRCA(&b.app, masterCaps)
		out = append(out, b.app)
	}
	sort.Slice(out, func(i, j int) bool {
		// Ghost sites (no docroot on disk) sink to the bottom — they
		// aren't real activity.
		if out[i].DocRootMissing != out[j].DocRootMissing {
			return !out[i].DocRootMissing
		}
		// Sort: apps with active issues first, then by CPU%, then by RSS.
		ci := criticalScore(out[i])
		cj := criticalScore(out[j])
		if ci != cj {
			return ci > cj
		}
		if out[i].CPUPct != out[j].CPUPct {
			return out[i].CPUPct > out[j].CPUPct
		}
		return out[i].RSSKB > out[j].RSSKB
	})
	return out
}

func criticalScore(a model.PHPFPMApp) int {
	score := 0
	for _, iss := range a.Issues {
		switch iss.Severity {
		case "crit":
			score += 100
		case "warn":
			score += 10
		case "info":
			score += 1
		}
	}
	return score
}

func stripQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}
