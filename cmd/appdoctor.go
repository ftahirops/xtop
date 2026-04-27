package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/engine"
)

// appDoctorFinding represents a single finding in the app doctor report.
type appDoctorFinding struct {
	severity string // "CRIT", "WARN", "INFO", "OK"
	category string
	problem  string
	impact   string
	fix      string
}

// collEntry represents a MongoDB collection entry in the db_list deep metric.
type collEntry struct {
	Name     string   `json:"name"`
	SizeMB   float64  `json:"size_mb"`
	Docs     int64    `json:"docs"`
	Indexes  int      `json:"indexes"`
	IdxNames []string `json:"idx_names"`
	ROps     int64    `json:"r_ops"`
	RAvgUs   int64    `json:"r_avg_us"`
	WOps     int64    `json:"w_ops"`
	WAvgUs   int64    `json:"w_avg_us"`
	ROpsRate float64  `json:"r_ops_rate"`
	WOpsRate float64  `json:"w_ops_rate"`
}

// dbEntry represents a MongoDB database entry in the db_list deep metric.
type dbEntry struct {
	Name        string      `json:"name"`
	SizeMB      float64     `json:"size_mb"`
	Collections int         `json:"collections"`
	Indexes     int         `json:"indexes"`
	Colls       []collEntry `json:"colls"`
}

// appReport holds the analyzed data for one application.
type appReport struct {
	ID          string
	DisplayName string
	AppType     string
	PID         int
	Port        int
	Version     string
	ConfigPath  string
	UptimeSec   int64
	// Computed stats
	AvgCPU      float64
	MaxCPU      float64
	MinCPU      float64
	AvgRSS      float64
	MaxRSS      float64
	AvgThreads  float64
	MaxFDs      int
	AvgConns    float64
	MaxConns    int
	HealthScore int
	HealthTrend string // "stable", "degrading", "improving"
	Issues      []string
	// Deep metrics (latest)
	Deep map[string]string
	// Findings
	Findings []appDoctorFinding
}

// appLatestInfo holds identity info from the latest snapshot.
type appLatestInfo struct {
	id          string
	displayName string
	appType     string
	pid         int
	port        int
	version     string
	configPath  string
	uptimeSec   int64
}

// runAppDoctor performs a deep multi-cycle application health analysis
// and saves a comprehensive report to a file.
func runAppDoctor(cfg Config) error {
	hostname, _ := os.Hostname()
	ts := time.Now()
	cycles := 10 // number of collection cycles
	interval := cfg.Interval
	if interval < 2*time.Second {
		interval = 3 * time.Second
	}

	// Handle ctrl+C gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("\n %s%s xtop app-doctor v%s %s — %s%s%s\n",
		B, BBlu+FBWht, Version, R, B, hostname, R)
	fmt.Printf(" %sDeep application health analysis with full report%s\n\n", D, R)

	// Phase 1: Discovery
	fmt.Printf(" %s[1/4]%s Discovering applications...\n", B+FBCyn, R)
	eng := engine.NewEngine(cfg.HistorySize, int(interval.Seconds()))
	eng.SetNoHysteresis(cfg.NoHysteresis)
	defer eng.Close()
	ticker := engine.Ticker(eng)

	// First tick to detect apps
	ticker.Tick()
	time.Sleep(interval)
	snap, _, _ := ticker.Tick()

	if snap == nil {
		return fmt.Errorf("failed to collect system snapshot")
	}

	apps := snap.Global.Apps.Instances
	if len(apps) == 0 {
		fmt.Printf("\n %sNo applications detected.%s\n", D, R)
		fmt.Printf(" %sMake sure database/web server processes are running.%s\n\n", D, R)
		return nil
	}

	// Show discovered apps
	fmt.Printf("\n %s%sDiscovered %d application(s):%s\n\n", B, FBGrn, len(apps), R)
	for i, app := range apps {
		health := fmt.Sprintf("%s%s OK %s", B, FBGrn, R)
		if app.HealthScore < 70 {
			health = fmt.Sprintf("%s%sCRIT%s", B, FBRed, R)
		} else if app.HealthScore < 90 {
			health = fmt.Sprintf("%sWARN%s", FBYel, R)
		}
		ver := app.Version
		if ver == "" {
			ver = "?"
		}
		deep := ""
		if app.HasDeepMetrics {
			deep = fmt.Sprintf("%s(deep metrics available)%s", FBGrn, R)
		} else if app.NeedsCreds {
			deep = fmt.Sprintf("%s(needs credentials for deep analysis)%s", FBYel, R)
		}
		fmt.Printf("   %s%d.%s %-15s PID %-7d Port %-6d v%-10s %s %s\n",
			B, i+1, R, app.DisplayName, app.PID, app.Port, ver, health, deep)
	}

	// Phase 2: Multi-cycle collection
	fmt.Printf("\n %s[2/4]%s Collecting %d samples over %s...\n\n",
		B+FBCyn, R, cycles, time.Duration(cycles)*interval)

	type sampleData struct {
		cpuPct       float64
		rssMB        float64
		threads      int
		fds          int
		connections  int
		healthScore  int
		healthIssues []string
		deep         map[string]string
	}

	// appID → []sampleData
	samples := make(map[string][]sampleData)
	// Keep the latest snapshot for report details
	var latestApps []appLatestInfo

	for cycle := 0; cycle < cycles; cycle++ {
		select {
		case <-sigCh:
			fmt.Printf("\n\n %sInterrupted — generating report with %d samples%s\n", FBYel, cycle, R)
			goto report
		default:
		}

		time.Sleep(interval)
		snap, _, _ = ticker.Tick()
		if snap == nil {
			continue
		}

		// Progress bar
		pct := float64(cycle+1) / float64(cycles) * 100
		bar := strings.Repeat("█", (cycle+1)*30/cycles) + strings.Repeat("░", 30-(cycle+1)*30/cycles)
		fmt.Fprintf(os.Stderr, "\r   %s %3.0f%% (%d/%d)", bar, pct, cycle+1, cycles)

		for _, app := range snap.Global.Apps.Instances {
			sd := sampleData{
				cpuPct:       app.CPUPct,
				rssMB:        app.RSSMB,
				threads:      app.Threads,
				fds:          app.FDs,
				connections:  app.Connections,
				healthScore:  app.HealthScore,
				healthIssues: app.HealthIssues,
			}
			if app.HasDeepMetrics {
				sd.deep = make(map[string]string)
				for k, v := range app.DeepMetrics {
					sd.deep[k] = v
				}
			}
			samples[app.ID] = append(samples[app.ID], sd)
		}

		// Update latest app info every cycle (in case of early interruption)
		{
			latestApps = nil
			for _, app := range snap.Global.Apps.Instances {
				latestApps = append(latestApps, appLatestInfo{
					id:          app.ID,
					displayName: app.DisplayName,
					appType:     app.AppType,
					pid:         app.PID,
					port:        app.Port,
					version:     app.Version,
					configPath:  app.ConfigPath,
					uptimeSec:   app.UptimeSec,
				})
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\r   %s 100%% (%d/%d)    \n\n",
		strings.Repeat("█", 30), cycles, cycles)

report:
	// Phase 3: Analysis
	fmt.Printf(" %s[3/4]%s Analyzing collected data...\n", B+FBCyn, R)

	var reports []appReport

	for _, la := range latestApps {
		samps := samples[la.id]
		if len(samps) == 0 {
			continue
		}

		// Find the latest sample with deep metrics
		var latestDeep map[string]string
		for i := len(samps) - 1; i >= 0; i-- {
			if len(samps[i].deep) > 0 {
				latestDeep = samps[i].deep
				break
			}
		}

		r := appReport{
			ID:          la.id,
			DisplayName: la.displayName,
			AppType:     la.appType,
			PID:         la.pid,
			Port:        la.port,
			Version:     la.version,
			ConfigPath:  la.configPath,
			UptimeSec:   la.uptimeSec,
			Deep:        latestDeep,
		}
		// Version fallback from deep metrics
		if r.Version == "" && latestDeep != nil {
			if v := latestDeep["version"]; v != "" {
				r.Version = v
			}
		}

		// Compute statistics
		var sumCPU, sumRSS, sumThreads, sumConns float64
		r.MinCPU = 999999
		maxFDs := 0
		maxConns := 0
		healthFirst := samps[0].healthScore
		healthLast := samps[len(samps)-1].healthScore

		for _, s := range samps {
			sumCPU += s.cpuPct
			sumRSS += s.rssMB
			sumThreads += float64(s.threads)
			sumConns += float64(s.connections)
			if s.cpuPct > r.MaxCPU {
				r.MaxCPU = s.cpuPct
			}
			if s.cpuPct < r.MinCPU {
				r.MinCPU = s.cpuPct
			}
			if s.rssMB > r.MaxRSS {
				r.MaxRSS = s.rssMB
			}
			if s.fds > maxFDs {
				maxFDs = s.fds
			}
			if s.connections > maxConns {
				maxConns = s.connections
			}
		}
		n := float64(len(samps))
		r.AvgCPU = sumCPU / n
		r.AvgRSS = sumRSS / n
		r.AvgThreads = sumThreads / n
		r.AvgConns = sumConns / n
		r.MaxFDs = maxFDs
		r.MaxConns = maxConns
		r.HealthScore = healthLast

		if healthLast < healthFirst-10 {
			r.HealthTrend = "degrading"
		} else if healthLast > healthFirst+10 {
			r.HealthTrend = "improving"
		} else {
			r.HealthTrend = "stable"
		}

		// Collect unique issues across all samples
		issueSet := make(map[string]bool)
		for _, s := range samps {
			for _, iss := range s.healthIssues {
				issueSet[iss] = true
			}
		}
		for iss := range issueSet {
			r.Issues = append(r.Issues, iss)
		}
		sort.Strings(r.Issues)

		// Generate findings based on collected data
		r.Findings = analyzeAppFindings(r)

		reports = append(reports, r)
	}

	// Phase 4: Generate report
	fmt.Printf(" %s[4/4]%s Generating report...\n\n", B+FBCyn, R)

	reportContent := generateAppDoctorReport(reports, hostname, ts, cycles, interval)

	// Save to file
	reportDir := "/tmp"
	if home, err := os.UserHomeDir(); err == nil {
		reportDir = home
	}
	fileName := fmt.Sprintf("xtop-app-doctor-%s-%s.md",
		hostname, ts.Format("2006-01-02-150405"))
	reportPath := filepath.Join(reportDir, fileName)

	if err := os.WriteFile(reportPath, []byte(reportContent), 0644); err != nil {
		// Fallback to /tmp
		reportPath = filepath.Join("/tmp", fileName)
		os.WriteFile(reportPath, []byte(reportContent), 0644)
	}

	// Print CLI summary
	printAppDoctorCLI(reports, hostname, ts)

	fmt.Printf("\n %s%s Report saved: %s %s\n", B, FBGrn, reportPath, R)
	fmt.Printf(" %sShare this file with your team for review.%s\n\n", D, R)

	// Exit code based on worst health
	worst := 0
	for _, r := range reports {
		if r.HealthScore < 70 && worst < 2 {
			worst = 2
		} else if r.HealthScore < 90 && worst < 1 {
			worst = 1
		}
	}
	if worst > 0 {
		return ExitCodeError{Code: worst}
	}
	return nil
}

// analyzeAppFindings generates detailed findings for an application.
func analyzeAppFindings(r appReport) []appDoctorFinding {
	var findings []appDoctorFinding

	// CPU analysis
	if r.AvgCPU > 80 {
		findings = append(findings, appDoctorFinding{
			severity: "CRIT",
			category: "CPU",
			problem:  fmt.Sprintf("Sustained high CPU usage (avg %.1f%%, peak %.1f%%)", r.AvgCPU, r.MaxCPU),
			impact:   "Application response times degraded, other processes starved",
			fix:      "Profile application for hot code paths. Check for runaway queries or tight loops",
		})
	} else if r.AvgCPU > 50 {
		findings = append(findings, appDoctorFinding{
			severity: "WARN",
			category: "CPU",
			problem:  fmt.Sprintf("Elevated CPU usage (avg %.1f%%, peak %.1f%%)", r.AvgCPU, r.MaxCPU),
			impact:   "Limited headroom for traffic spikes",
			fix:      "Monitor trend — consider scaling if load increases",
		})
	}

	// Memory analysis
	if r.MaxRSS > 4096 {
		findings = append(findings, appDoctorFinding{
			severity: "WARN",
			category: "Memory",
			problem:  fmt.Sprintf("High memory usage (avg %.0f MB, peak %.0f MB)", r.AvgRSS, r.MaxRSS),
			impact:   "Risk of OOM kill if system memory is constrained",
			fix:      "Review application memory settings and connection pool sizes",
		})
	}

	// Connection analysis
	if r.MaxConns > 500 {
		findings = append(findings, appDoctorFinding{
			severity: "WARN",
			category: "Connections",
			problem:  fmt.Sprintf("High connection count (avg %.0f, peak %d)", r.AvgConns, r.MaxConns),
			impact:   "Connection exhaustion risk, each connection uses memory and FDs",
			fix:      "Review client connection pool sizes. Consider connection pooling proxy",
		})
	}

	// FD analysis
	if r.MaxFDs > 10000 {
		sev := "WARN"
		if r.MaxFDs > 50000 {
			sev = "CRIT"
		}
		findings = append(findings, appDoctorFinding{
			severity: sev,
			category: "File Descriptors",
			problem:  fmt.Sprintf("High FD count (%d)", r.MaxFDs),
			impact:   "Risk of hitting FD limit — new connections and file opens will fail",
			fix:      "Check ulimit -n. Review connection leaks. Consider raising limits if needed",
		})
	}

	// App-specific deep metric findings
	if r.Deep != nil {
		findings = append(findings, analyzeDeepFindings(r)...)
	}

	return findings
}

// analyzeDeepFindings checks app-type-specific deep metrics.
func analyzeDeepFindings(r appReport) []appDoctorFinding {
	var findings []appDoctorFinding
	dm := r.Deep

	switch r.AppType {
	case "mongodb":
		// Connection pressure
		connCur, _ := strconv.ParseFloat(dm["conn_current"], 64)
		connAvail, _ := strconv.ParseFloat(dm["conn_available"], 64)
		if connAvail > 0 {
			usage := connCur / (connCur + connAvail) * 100
			if usage > 80 {
				findings = append(findings, appDoctorFinding{
					severity: "CRIT",
					category: "Connections",
					problem:  fmt.Sprintf("MongoDB connection usage at %.0f%% (%.0f/%.0f)", usage, connCur, connCur+connAvail),
					impact:   "New connections will be rejected when limit is reached",
					fix:      "Reduce maxPoolSize on application servers. Current connections are too high",
				})
			}
		}

		// Cache pressure
		if v := dm["cache_usage_pct"]; v != "" {
			pct, _ := strconv.ParseFloat(v, 64)
			if pct > 95 {
				findings = append(findings, appDoctorFinding{
					severity: "CRIT",
					category: "WiredTiger Cache",
					problem:  fmt.Sprintf("Cache usage at %.1f%% — approaching eviction pressure", pct),
					impact:   "Reads will slow down as data is evicted from cache to disk",
					fix:      "Increase WiredTiger cache size or add more RAM to server",
				})
			} else if pct > 80 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "WiredTiger Cache",
					problem:  fmt.Sprintf("Cache usage at %.1f%%", pct),
					impact:   "Limited cache headroom for working set growth",
					fix:      "Monitor — may need cache size increase if data grows",
				})
			}
		}

		// Replication lag
		if v := dm["repl_lag_sec"]; v != "" {
			lag, _ := strconv.ParseFloat(v, 64)
			if lag > 60 {
				findings = append(findings, appDoctorFinding{
					severity: "CRIT",
					category: "Replication",
					problem:  fmt.Sprintf("Replication lag: %.0f seconds", lag),
					impact:   "Secondary reads serving stale data. Risk of rollback on failover",
					fix:      "Check oplog size, disk I/O on secondary, and network bandwidth",
				})
			} else if lag > 10 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "Replication",
					problem:  fmt.Sprintf("Replication lag: %.1f seconds", lag),
					impact:   "Secondary reads may return slightly stale data",
					fix:      "Monitor — check secondary disk performance",
				})
			}
		}

		// Lock queue
		if v := dm["lock_queue_total"]; v != "" {
			q, _ := strconv.Atoi(v)
			if q > 10 {
				findings = append(findings, appDoctorFinding{
					severity: "CRIT",
					category: "Lock Contention",
					problem:  fmt.Sprintf("Lock queue depth: %d operations waiting", q),
					impact:   "Operations are blocking each other — causes latency spikes",
					fix:      "Check for long-running writes, large unindexed queries, or schema lock",
				})
			}
		}

		// Collection scan rate (from index analysis data)
		if v := dm["collection_scans_rate"]; v != "" {
			rate, _ := strconv.ParseFloat(v, 64)
			if rate > 10 {
				findings = append(findings, appDoctorFinding{
					severity: "CRIT",
					category: "Missing Indexes",
					problem:  fmt.Sprintf("%.0f collection scans/sec — queries without indexes", rate),
					impact:   "Each scan reads every document in the collection, causing high CPU and I/O",
					fix:      "Enable profiling (db.setProfilingLevel(1, {slowms: 50})) and create missing indexes",
				})
			}
		}

		// Page faults
		if v := dm["page_faults_rate"]; v != "" {
			rate, _ := strconv.ParseFloat(v, 64)
			if rate > 100 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "Page Faults",
					problem:  fmt.Sprintf("%.0f page faults/sec — working set exceeds RAM", rate),
					impact:   "Frequent disk reads instead of cache hits, slow query performance",
					fix:      "Add more RAM or reduce working set size. Check WiredTiger cache configuration",
				})
			}
		}

	case "mysql":
		// Buffer pool hit ratio
		if v := dm["buffer_pool_hit_ratio"]; v != "" {
			ratio, _ := strconv.ParseFloat(v, 64)
			if ratio < 95 && ratio > 0 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "Buffer Pool",
					problem:  fmt.Sprintf("Buffer pool hit ratio: %.1f%% (should be >99%%)", ratio),
					impact:   "Reads going to disk instead of memory — slow queries",
					fix:      "Increase innodb_buffer_pool_size (recommend 70-80%% of available RAM)",
				})
			}
		}

		// Thread usage
		if running := dm["threads_running"]; running != "" {
			tr, _ := strconv.Atoi(running)
			if tr > 50 {
				findings = append(findings, appDoctorFinding{
					severity: "CRIT",
					category: "Thread Contention",
					problem:  fmt.Sprintf("%d threads running simultaneously", tr),
					impact:   "Excessive thread contention causes CPU waste and slow queries",
					fix:      "Check for slow queries, missing indexes, or lock contention",
				})
			}
		}

		// Slow queries
		if v := dm["slow_queries_rate"]; v != "" {
			rate, _ := strconv.ParseFloat(v, 64)
			if rate > 1 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "Slow Queries",
					problem:  fmt.Sprintf("%.1f slow queries/sec", rate),
					impact:   "Slow queries consume CPU and block other operations",
					fix:      "Review slow query log. Check EXPLAIN on frequent queries for missing indexes",
				})
			}
		}

	case "redis":
		// Memory usage vs maxmemory
		if v := dm["used_memory_pct"]; v != "" {
			pct, _ := strconv.ParseFloat(v, 64)
			if pct > 90 {
				findings = append(findings, appDoctorFinding{
					severity: "CRIT",
					category: "Memory",
					problem:  fmt.Sprintf("Redis memory at %.0f%% of maxmemory", pct),
					impact:   "Key eviction active — data loss if no proper eviction policy",
					fix:      "Increase maxmemory or review data retention. Check eviction policy",
				})
			}
		}

		// Hit ratio
		if v := dm["hit_ratio"]; v != "" {
			ratio, _ := strconv.ParseFloat(v, 64)
			if ratio < 80 && ratio > 0 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "Cache Efficiency",
					problem:  fmt.Sprintf("Cache hit ratio: %.1f%%", ratio),
					impact:   "Application frequently requesting missing keys — cache not effective",
					fix:      "Review TTL settings. Check if working set fits in memory",
				})
			}
		}

	case "postgresql":
		// Cache hit ratio
		if v := dm["cache_hit_ratio"]; v != "" {
			ratio, _ := strconv.ParseFloat(v, 64)
			if ratio < 95 && ratio > 0 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "Cache",
					problem:  fmt.Sprintf("Cache hit ratio: %.1f%% (should be >99%%)", ratio),
					impact:   "Frequent disk reads — slow query performance",
					fix:      "Increase shared_buffers and effective_cache_size",
				})
			}
		}

	case "nginx":
		// Worker connections
		if active := dm["active_connections"]; active != "" {
			a, _ := strconv.Atoi(active)
			if a > 5000 {
				findings = append(findings, appDoctorFinding{
					severity: "WARN",
					category: "Connections",
					problem:  fmt.Sprintf("%d active connections", a),
					impact:   "High connection load — risk of worker_connections limit",
					fix:      "Review worker_connections setting and upstream health",
				})
			}
		}

	case "elasticsearch":
		// Cluster health
		if v := dm["cluster_status"]; v == "red" {
			findings = append(findings, appDoctorFinding{
				severity: "CRIT",
				category: "Cluster Health",
				problem:  "Elasticsearch cluster status: RED",
				impact:   "Some primary shards are unassigned — data loss risk",
				fix:      "Check node status, disk space, and shard allocation",
			})
		} else if v == "yellow" {
			findings = append(findings, appDoctorFinding{
				severity: "WARN",
				category: "Cluster Health",
				problem:  "Elasticsearch cluster status: YELLOW",
				impact:   "Some replica shards unassigned — reduced redundancy",
				fix:      "Check if enough nodes available for replica allocation",
			})
		}
	}

	return findings
}

// printAppDoctorCLI prints the analysis summary to terminal.
func printAppDoctorCLI(reports []appReport, hostname string, ts time.Time) {
	fmt.Printf(" %s══════════════════════════════════════════════════════════%s\n", D, R)
	fmt.Printf(" %s%s  APPLICATION HEALTH REPORT  %s  %s  %s\n",
		B+BBlu+FBWht, " ", R, hostname, ts.Format("2006-01-02 15:04:05"))
	fmt.Printf(" %s══════════════════════════════════════════════════════════%s\n\n", D, R)

	totalCrit := 0
	totalWarn := 0

	for _, r := range reports {
		// Health badge
		badge := fmt.Sprintf("%s%s OK %s", B, FBGrn, R)
		if r.HealthScore < 70 {
			badge = fmt.Sprintf("%s%sCRIT%s", B, FBRed, R)
		} else if r.HealthScore < 90 {
			badge = fmt.Sprintf("%sWARN%s", FBYel, R)
		}

		// App header
		ver := r.Version
		if ver == "" {
			ver = "unknown"
		}
		uptime := formatUptime(r.UptimeSec)
		fmt.Printf(" %s%s%s  %s  Health: %d/100  v%s  uptime: %s\n",
			B, r.DisplayName, R, badge, r.HealthScore, ver, uptime)
		fmt.Printf(" %s──────────────────────────────────────────────────────%s\n", D, R)

		// Resource summary
		fmt.Printf("   %sResources:%s  CPU avg %.1f%% (peak %.1f%%)  |  RSS %.0f MB  |  Conns %d  |  FDs %d\n",
			D, R, r.AvgCPU, r.MaxCPU, r.AvgRSS, r.MaxConns, r.MaxFDs)

		// Health trend
		trend := r.HealthTrend
		trendColor := D
		if trend == "degrading" {
			trendColor = FBRed
		} else if trend == "improving" {
			trendColor = FBGrn
		}
		fmt.Printf("   %sTrend:%s     %s%s%s during analysis\n", D, R, trendColor, trend, R)

		// Findings
		if len(r.Findings) > 0 {
			fmt.Printf("\n   %sFindings:%s\n", B, R)
			for _, f := range r.Findings {
				icon := fmt.Sprintf("%s +%s", FBGrn, R)
				switch f.severity {
				case "CRIT":
					icon = fmt.Sprintf("%s%s!!%s", B, FBRed, R)
					totalCrit++
				case "WARN":
					icon = fmt.Sprintf("%s!!%s", FBYel, R)
					totalWarn++
				case "INFO":
					icon = fmt.Sprintf("%s i%s", FCyn, R)
				}
				fmt.Printf("   %s %s[%s]%s %s\n", icon, D, f.category, R, f.problem)
				if f.impact != "" {
					fmt.Printf("      %sImpact:%s %s\n", D, R, f.impact)
				}
				if f.fix != "" {
					fmt.Printf("      %sFix:%s    %s\n", D, R, f.fix)
				}
			}
		} else {
			fmt.Printf("   %sNo issues detected%s\n", FBGrn, R)
		}

		// Health issues from the collector
		if len(r.Issues) > 0 && len(r.Findings) == 0 {
			fmt.Printf("\n   %sHealth Issues:%s\n", B, R)
			for _, iss := range r.Issues {
				fmt.Printf("   %s!!%s %s\n", FBYel, R, iss)
			}
		}

		fmt.Println()
	}

	// Summary
	fmt.Printf(" %s══════════════════════════════════════════════════════════%s\n", D, R)
	if totalCrit > 0 {
		fmt.Printf(" %s%s %d critical, %d warning(s) across %d app(s)%s\n",
			B, FBRed, totalCrit, totalWarn, len(reports), R)
	} else if totalWarn > 0 {
		fmt.Printf(" %s %d warning(s) across %d app(s)%s\n",
			FBYel, totalWarn, len(reports), R)
	} else {
		fmt.Printf(" %s All %d app(s) healthy%s\n", FBGrn, len(reports), R)
	}
	fmt.Printf(" %s══════════════════════════════════════════════════════════%s\n", D, R)
}

// generateAppDoctorReport creates the full Markdown report.
func generateAppDoctorReport(reports []appReport, hostname string, ts time.Time, cycles int, interval time.Duration) string {
	var sb strings.Builder

	sb.WriteString("# xtop App Doctor Report\n\n")
	sb.WriteString(fmt.Sprintf("**Host:** %s  \n", hostname))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", ts.Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("**Version:** xtop v%s  \n", Version))
	sb.WriteString(fmt.Sprintf("**Analysis:** %d samples over %s (interval %s)  \n\n",
		cycles, time.Duration(cycles)*interval, interval))

	// Executive summary
	sb.WriteString("## Executive Summary\n\n")
	totalCrit := 0
	totalWarn := 0
	for _, r := range reports {
		for _, f := range r.Findings {
			switch f.severity {
			case "CRIT":
				totalCrit++
			case "WARN":
				totalWarn++
			}
		}
	}

	if totalCrit > 0 {
		sb.WriteString(fmt.Sprintf("**Status: CRITICAL** — %d critical issue(s), %d warning(s) across %d application(s)\n\n",
			totalCrit, totalWarn, len(reports)))
	} else if totalWarn > 0 {
		sb.WriteString(fmt.Sprintf("**Status: WARNING** — %d warning(s) across %d application(s)\n\n",
			totalWarn, len(reports)))
	} else {
		sb.WriteString(fmt.Sprintf("**Status: HEALTHY** — All %d application(s) operating normally\n\n",
			len(reports)))
	}

	// Overview table
	sb.WriteString("## Application Overview\n\n")
	overviewRows := [][]string{{"Application", "Version", "Health", "CPU Avg", "RSS", "Connections", "Uptime", "Findings"}}
	for _, r := range reports {
		ver := r.Version
		if ver == "" {
			ver = "—"
		}
		health := "OK"
		if r.HealthScore < 70 {
			health = "**CRIT**"
		} else if r.HealthScore < 90 {
			health = "WARN"
		}
		overviewRows = append(overviewRows, []string{
			r.DisplayName, ver, fmt.Sprintf("%s (%d/100)", health, r.HealthScore),
			fmt.Sprintf("%.1f%%", r.AvgCPU), fmt.Sprintf("%.0f MB", r.AvgRSS),
			fmt.Sprintf("%d", r.MaxConns), formatUptime(r.UptimeSec),
			fmt.Sprintf("%d", len(r.Findings)),
		})
	}
	sb.WriteString(mdTable(overviewRows))
	sb.WriteString("\n")

	// Detailed per-app sections
	for _, r := range reports {
		sb.WriteString(fmt.Sprintf("---\n\n## %s\n\n", r.DisplayName))

		// Identity
		sb.WriteString("### Instance Details\n\n")
		idRows := [][]string{{"Property", "Value"}}
		idRows = append(idRows, []string{"Type", r.AppType})
		ver := r.Version
		if ver == "" {
			ver = "—"
		}
		idRows = append(idRows, []string{"Version", ver})
		idRows = append(idRows, []string{"PID", fmt.Sprintf("%d", r.PID)})
		if r.Port > 0 {
			idRows = append(idRows, []string{"Port", fmt.Sprintf("%d", r.Port)})
		}
		idRows = append(idRows, []string{"Uptime", formatUptime(r.UptimeSec)})
		if r.ConfigPath != "" {
			idRows = append(idRows, []string{"Config", fmt.Sprintf("`%s`", r.ConfigPath)})
		}
		idRows = append(idRows, []string{"Health Score", fmt.Sprintf("%d/100", r.HealthScore)})
		idRows = append(idRows, []string{"Health Trend", r.HealthTrend})
		sb.WriteString(mdTable(idRows))
		sb.WriteString("\n")

		// Resource metrics with status assessment
		sb.WriteString("### Resource Usage\n\n")

		// CPU assessment
		cpuStatus, cpuBP := "OK", "< 70% avg"
		if r.MaxCPU > 95 {
			cpuStatus = "**CRIT**"
		} else if r.AvgCPU > 70 || r.MaxCPU > 85 {
			cpuStatus = "WARN"
		}
		// Memory assessment
		memStatus, memBP := "OK", "Stable, no growth"
		if r.MaxRSS > 4096 {
			memStatus = "WARN"
			memBP = "Review if RSS justified for workload"
		}
		if r.MaxRSS > 8192 {
			memStatus = "**CRIT**"
			memBP = "Likely memory leak or oversized cache"
		}
		// Thread assessment
		thStatus, thBP := "OK", "< 200 threads"
		if r.AvgThreads > 500 {
			thStatus = "**CRIT**"
			thBP = "Excessive — review thread pool config"
		} else if r.AvgThreads > 200 {
			thStatus = "WARN"
			thBP = "High — check for thread leaks"
		}
		// Connection assessment
		connStatus, connBP := "OK", "< 500 connections"
		if r.MaxConns > 1000 {
			connStatus = "**CRIT**"
			connBP = "**Reduce maxPoolSize on app servers**"
		} else if r.MaxConns > 500 {
			connStatus = "WARN"
			connBP = "Review connection pool sizing"
		}
		// FD assessment
		fdStatus, fdBP := "OK", "< 50K"
		if r.MaxFDs > 50000 {
			fdStatus = "**CRIT**"
			fdBP = "Near system limit — raise ulimit"
		} else if r.MaxFDs > 20000 {
			fdStatus = "WARN"
			fdBP = "High — check for FD leaks"
		}
		resRows := [][]string{
			{"Metric", "Average", "Peak", "Status", "Best Practice"},
			{"CPU", fmt.Sprintf("%.1f%%", r.AvgCPU), fmt.Sprintf("%.1f%%", r.MaxCPU), cpuStatus, cpuBP},
			{"Memory (RSS)", fmt.Sprintf("%.0f MB", r.AvgRSS), fmt.Sprintf("%.0f MB", r.MaxRSS), memStatus, memBP},
			{"Threads", fmt.Sprintf("%.0f", r.AvgThreads), "—", thStatus, thBP},
			{"Connections", fmt.Sprintf("%.0f", r.AvgConns), fmt.Sprintf("%d", r.MaxConns), connStatus, connBP},
			{"File Descriptors", "—", fmt.Sprintf("%d", r.MaxFDs), fdStatus, fdBP},
		}
		sb.WriteString(mdTable(resRows))
		sb.WriteString("\n")

		// Deep metrics — app-type-specific structured output
		if len(r.Deep) > 0 {
			writeAppDoctorDeepMetrics(&sb, r)
		}

		// Findings
		if len(r.Findings) > 0 {
			sb.WriteString("### Findings\n\n")
			for i, f := range r.Findings {
				icon := "OK"
				switch f.severity {
				case "CRIT":
					icon = "**[CRIT]**"
				case "WARN":
					icon = "**[WARN]**"
				case "INFO":
					icon = "[INFO]"
				}
				sb.WriteString(fmt.Sprintf("%d. %s **%s**: %s\n", i+1, icon, f.category, f.problem))
				if f.impact != "" {
					sb.WriteString(fmt.Sprintf("   - **Impact:** %s\n", f.impact))
				}
				if f.fix != "" {
					sb.WriteString(fmt.Sprintf("   - **Fix:** %s\n", f.fix))
				}
				sb.WriteString("\n")
			}
		} else {
			sb.WriteString("### Findings\n\nNo issues detected. Application is operating normally.\n\n")
		}

		// Health issues from collector
		if len(r.Issues) > 0 {
			sb.WriteString("### Health Warnings\n\n")
			for _, iss := range r.Issues {
				sb.WriteString(fmt.Sprintf("- %s\n", iss))
			}
			sb.WriteString("\n")
		}
	}

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Generated by [xtop](https://github.com/ftahirops/xtop) v%s on %s*\n",
		Version, ts.Format("2006-01-02 15:04:05")))

	return sb.String()
}

// writeAppDoctorDeepMetrics writes structured deep metrics for the report.
func writeAppDoctorDeepMetrics(sb *strings.Builder, r appReport) {
	dm := r.Deep

	switch r.AppType {
	case "mongodb":
		writeMongoDeepMetrics(sb, dm)
	default:
		// Generic deep metrics with status assessment
		sb.WriteString("### Application Metrics\n\n")
		var keys []string
		for k := range dm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		genRows := [][]string{{"Metric", "Value", "Status"}}
		for _, k := range keys {
			v := dm[k]
			if v == "" || len(v) > 200 {
				continue
			}
			status := assessGenericMetric(k, v)
			genRows = append(genRows, []string{strings.ReplaceAll(k, "_", " "), v, status})
		}
		sb.WriteString(mdTable(genRows))
		sb.WriteString("\n")
	}
}

// assessGenericMetric provides status assessment for common metric patterns.
func assessGenericMetric(key, value string) string {
	v, _ := strconv.ParseFloat(value, 64)
	kl := strings.ToLower(key)

	switch {
	// Hit ratios (higher is better)
	case strings.Contains(kl, "hit_ratio") || strings.Contains(kl, "hit_rate") || strings.Contains(kl, "cache_hit"):
		if v > 99 {
			return "OK — excellent"
		} else if v > 95 {
			return "OK"
		} else if v > 80 {
			return "WARN — below 95% target"
		}
		return "**CRIT** — poor cache efficiency"

	// Error/reject counts (lower is better)
	case strings.Contains(kl, "error") || strings.Contains(kl, "reject") || strings.Contains(kl, "fail") || strings.Contains(kl, "refused"):
		if v == 0 {
			return "OK"
		} else if v < 10 {
			return "WARN"
		}
		return "**CRIT**"

	// Percentages
	case strings.Contains(kl, "_pct") || strings.Contains(kl, "percent") || strings.Contains(kl, "usage"):
		if v > 95 {
			return "**CRIT** — near capacity"
		} else if v > 80 {
			return "WARN — elevated"
		}
		return "OK"

	// Latency
	case strings.Contains(kl, "latency") || strings.Contains(kl, "avg_ms") || strings.Contains(kl, "response_time"):
		if v > 1000 {
			return "**CRIT** — very slow"
		} else if v > 100 {
			return "WARN — slow"
		}
		return "OK"

	// Slow queries
	case strings.Contains(kl, "slow"):
		if v > 100 {
			return "**CRIT**"
		} else if v > 10 {
			return "WARN"
		}
		return "OK"

	// Queue depth
	case strings.Contains(kl, "queue") || strings.Contains(kl, "waiting"):
		if v > 50 {
			return "**CRIT** — contention"
		} else if v > 10 {
			return "WARN"
		}
		return "OK"
	}

	return "—"
}

// writeMongoDeepMetrics writes executive-grade MongoDB assessment with status ratings per metric.
func writeMongoDeepMetrics(sb *strings.Builder, dm map[string]string) {
	pfv := func(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }
	piv := func(s string) int { v, _ := strconv.Atoi(s); return v }

	// ── Optimization Score ──
	optScore := 100
	var optIssues []string
	defer func() {
		// Insert optimization score at top (rendered after all analysis)
	}()

	// ── Connection Health ──
	sb.WriteString("### Connection Health\n\n")
	connRows := [][]string{{"Metric", "Value", "Status", "Best Practice"}}
	if v := dm["conn_current"]; v != "" {
		curr := piv(v)
		avail := piv(dm["conn_available"])
		total := curr + avail
		usePct := float64(0)
		if total > 0 {
			usePct = float64(curr) / float64(total) * 100
		}
		status, bp := "OK", "< 50% of available (industry std: 200-500 per replica set)"
		if usePct > 80 || curr > 1000 {
			status, bp = "**CRIT**", "**Connection exhaustion risk — reduce maxPoolSize to 10-20 per app server**"
			optScore -= 25
			optIssues = append(optIssues, "Connection pool oversized")
		} else if usePct > 50 || curr > 500 {
			status, bp = "WARN", "Reduce maxPoolSize per app server to 10-20 (MongoDB recommends 100 per app)"
			optScore -= 10
			optIssues = append(optIssues, "Connection count elevated")
		}
		connRows = append(connRows, []string{"Current / Available", fmt.Sprintf("%d / %d (%.0f%% used)", curr, total, usePct), status, bp})
	}
	if v := dm["conn_rejected"]; v != "" && v != "0" {
		connRows = append(connRows, []string{"Rejected Connections", v, "**CRIT**", "Should be 0 — increase net.maxIncomingConnections"})
		optScore -= 20
		optIssues = append(optIssues, fmt.Sprintf("%s connections rejected", v))
	}
	if v := dm["conn_total_created"]; v != "" {
		total := pfv(v)
		status, bp := "OK", "Low churn = healthy connection pooling"
		if total > 1e6 {
			status, bp = "WARN", "High churn — ensure apps use connection pooling, set maxIdleTimeMS: 60000"
			optScore -= 5
		}
		connRows = append(connRows, []string{"Lifetime Created", fmtLargeNum(v), status, bp})
	}
	sb.WriteString(mdTable(connRows))
	sb.WriteString("\n")

	// ── WiredTiger Cache ──
	sb.WriteString("### WiredTiger Cache\n\n")
	cacheRows := [][]string{{"Metric", "Value", "Status", "Best Practice"}}
	if used := dm["cache_used_mb"]; used != "" {
		maxC := dm["cache_max_mb"]
		usedF := pfv(used)
		maxF := pfv(maxC)
		pct := float64(0)
		if maxF > 0 {
			pct = usedF / maxF * 100
		}
		status, bp := "OK", "Industry std: cache < 80% (50% of RAM or cacheSizeGB)"
		if pct > 95 {
			status, bp = "**CRIT**", "**Active eviction — increase RAM or cacheSizeGB**"
			optScore -= 20
			optIssues = append(optIssues, fmt.Sprintf("Cache at %.0f%%", pct))
		} else if pct > 80 {
			status, bp = "WARN", "Approaching eviction threshold"
			optScore -= 10
		}
		cacheRows = append(cacheRows, []string{"Cache Usage", fmt.Sprintf("%.0f / %.0f MB (%.0f%%)", usedF, maxF, pct), status, bp})
	}
	if v := dm["cache_dirty_mb"]; v != "" {
		dirty := pfv(v)
		maxF := pfv(dm["cache_max_mb"])
		dirtyPct := float64(0)
		if maxF > 0 {
			dirtyPct = dirty / maxF * 100
		}
		status, bp := "OK", "Industry std: dirty pages < 5% of cache"
		if dirtyPct > 20 || dirty > 500 {
			status, bp = "**CRIT**", "**Heavy write pressure — check disk I/O**"
			optScore -= 15
			optIssues = append(optIssues, "Cache dirty pages excessive")
		} else if dirtyPct > 5 || dirty > 100 {
			status, bp = "WARN", "Elevated dirty pages"
			optScore -= 5
		}
		cacheRows = append(cacheRows, []string{"Dirty Pages", fmt.Sprintf("%.0f MB (%.1f%% of cache)", dirty, dirtyPct), status, bp})
	}
	if v := dm["mem_resident_mb"]; v != "" {
		mem := pfv(v)
		status := "OK"
		bp := "Should be <= available RAM (leave 20%+ free)"
		if mem > 16384 {
			status = "INFO"
			bp = fmt.Sprintf("%.1f GB resident — verify host has sufficient RAM", mem/1024)
		}
		cacheRows = append(cacheRows, []string{"Resident Memory", fmt.Sprintf("%.0f MB (%.1f GB)", mem, mem/1024), status, bp})
	}
	sb.WriteString(mdTable(cacheRows))
	sb.WriteString("\n")

	// ── Lock & Concurrency ──
	sb.WriteString("### Lock & Concurrency\n\n")
	lockRows := [][]string{{"Metric", "Value", "Status", "Best Practice"}}
	if v := dm["lock_queue_total"]; v != "" {
		lq := piv(v)
		status, bp := "OK", "Should be 0 in well-tuned deployment"
		if lq > 50 {
			status, bp = "**CRIT**", "**Lock contention — check db.currentOp() for long ops**"
			optScore -= 20
			optIssues = append(optIssues, fmt.Sprintf("Lock queue: %d", lq))
		} else if lq > 5 {
			status, bp = "WARN", "Some contention — review ops holding locks > 100ms"
			optScore -= 5
		}
		lockRows = append(lockRows, []string{"Lock Queue", fmt.Sprintf("%d", lq), status, bp})
	}
	if v := dm["active_readers"]; v != "" {
		ar := piv(v)
		aw := piv(dm["active_writers"])
		total := ar + aw
		status, bp := "OK", "Industry std: < 50 combined"
		if total > 100 {
			status, bp = "**CRIT**", "**Too many concurrent operations**"
			optScore -= 15
		} else if total > 50 {
			status, bp = "WARN", "Check for slow queries or missing indexes"
			optScore -= 5
		}
		rwRatio := "read-heavy"
		if aw > 0 {
			rwRatio = fmt.Sprintf("%.1f:1", float64(ar)/float64(aw))
		}
		lockRows = append(lockRows, []string{"Active Readers", fmt.Sprintf("%d", ar), status, bp})
		lockRows = append(lockRows, []string{"Active Writers", fmt.Sprintf("%d", aw), "—", "Read/Write ratio: " + rwRatio})
	}
	sb.WriteString(mdTable(lockRows))
	sb.WriteString("\n")

	// ── Operations ──
	sb.WriteString("### Operations\n\n")
	opRows := [][]string{{"Operation", "Total", "Rate (/s)", "Status", "Assessment"}}
	opKeys := []struct{ key, label string }{
		{"op_query", "Queries"},
		{"op_insert", "Inserts"},
		{"op_update", "Updates"},
		{"op_delete", "Deletes"},
		{"op_getmore", "GetMore"},
		{"op_command", "Commands"},
	}
	for _, ok := range opKeys {
		total := dm[ok.key]
		rate := dm[ok.key+"_rate"]
		if total == "" {
			continue
		}
		rateStr := "—"
		status, assess := "OK", "Normal"
		if rate != "" && rate != "0.0" {
			rateStr = rate
			rv := pfv(rate)
			if rv > 10000 {
				status, assess = "**HIGH**", "Verify workload is expected"
			} else if rv > 5000 {
				status, assess = "Elevated", "Monitor for latency spikes"
			} else if rv > 1000 {
				assess = "Active workload"
			}
		}
		opRows = append(opRows, []string{ok.label, fmtLargeNum(total), rateStr, status, assess})
	}
	sb.WriteString(mdTable(opRows))
	sb.WriteString("\n")

	// ── Query Efficiency ──
	collScan := dm["collection_scans"]
	scanOrder := dm["scan_and_order"]
	scannedKeys := dm["scanned_keys"]
	scannedObjs := dm["scanned_objects"]
	if collScan != "" || scanOrder != "" || scannedKeys != "" {
		sb.WriteString("### Query Efficiency\n\n")
		qeRows := [][]string{{"Metric", "Total", "Rate (/s)", "Status", "Assessment"}}
		if scannedKeys != "" && scannedObjs != "" {
			keys := pfv(scannedKeys)
			objs := pfv(scannedObjs)
			ratio := float64(0)
			if objs > 0 {
				ratio = keys / objs
			}
			status, assess := "OK", "Good index coverage"
			if ratio < 0.5 && objs > 1000 {
				status, assess = "**CRIT**", "**Missing indexes — very few keys vs docs**"
				optScore -= 20
				optIssues = append(optIssues, "Poor index coverage")
			} else if ratio < 1 && objs > 1000 {
				status, assess = "WARN", "Some queries scan more docs than keys"
				optScore -= 10
			}
			qeRows = append(qeRows, []string{"Keys/Docs Scanned",
				fmt.Sprintf("%s / %s (ratio: %.2f)", fmtLargeNum(scannedKeys), fmtLargeNum(scannedObjs), ratio),
				"—", status, assess})
		}
		if collScan != "" {
			rate := dm["collection_scans_rate"]
			if rate == "" {
				rate = "—"
			}
			status, assess := "OK", "No collection scans (ideal)"
			rv := pfv(rate)
			cs := pfv(collScan)
			if rv > 100 || cs > 100000 {
				status, assess = "**CRIT**", "**Full table scans — add indexes**"
				optScore -= 25
				optIssues = append(optIssues, "Excessive collection scans")
			} else if rv > 10 || cs > 10000 {
				status, assess = "WARN", "Enable profiling: db.setProfilingLevel(1, {slowms:50})"
				optScore -= 10
			}
			qeRows = append(qeRows, []string{"Collection Scans", fmtLargeNum(collScan), rate, status, assess})
		}
		if scanOrder != "" {
			rate := dm["scan_and_order_rate"]
			if rate == "" {
				rate = "—"
			}
			status, assess := "OK", "Sorts using indexes"
			rv := pfv(rate)
			if rv > 50 {
				status, assess = "**CRIT**", "**In-memory sorts — add compound indexes**"
				optScore -= 15
				optIssues = append(optIssues, "In-memory sorts (scan_and_order)")
			} else if rv > 5 {
				status, assess = "WARN", "Some in-memory sorts"
				optScore -= 5
			}
			qeRows = append(qeRows, []string{"Scan & Order", fmtLargeNum(scanOrder), rate, status, assess})
		}
		sb.WriteString(mdTable(qeRows))
		sb.WriteString("\n")
	}

	// ── Page Faults ──
	if v := dm["page_faults"]; v != "" {
		pfVal := piv(v)
		if pfVal > 0 {
			sb.WriteString("### Page Faults\n\n")
			status, assess := "OK", "Minimal — working set fits in RAM"
			if pfVal > 10000 {
				status, assess = "**CRIT**", "**Working set exceeds RAM — add memory**"
				optScore -= 20
				optIssues = append(optIssues, "Heavy page faulting")
			} else if pfVal > 1000 {
				status, assess = "WARN", "Monitor — may need more RAM"
				optScore -= 5
			}
			pfRows := [][]string{
				{"Metric", "Value", "Status", "Assessment"},
				{"Page Faults", fmtLargeNum(fmt.Sprintf("%d", pfVal)), status, assess},
			}
			sb.WriteString(mdTable(pfRows))
			sb.WriteString("\n")
		}
	}

	// ── Network Throughput ──
	sb.WriteString("### Network Throughput\n\n")
	netRows := [][]string{{"Metric", "Value", "Status", "Assessment"}}
	if v := dm["net_bytes_in"]; v != "" {
		bps := pfv(v)
		status, assess := "OK", "Normal inbound traffic"
		if bps > 1e9 {
			status, assess = "**HIGH**", "Potential large bulk inserts"
		}
		netRows = append(netRows, []string{"Bytes In", fmtBytes(v), status, assess})
	}
	if v := dm["net_bytes_out"]; v != "" {
		bps := pfv(v)
		status, assess := "OK", "Normal outbound traffic"
		if bps > 1e10 {
			status, assess = "**HIGH**", "Check for unindexed queries returning large results"
		} else if bps > 1e9 {
			status, assess = "Elevated", "Ensure projections limit returned fields"
		}
		netRows = append(netRows, []string{"Bytes Out", fmtBytes(v), status, assess})
	}
	if v := dm["net_num_requests"]; v != "" {
		netRows = append(netRows, []string{"Total Requests", fmtLargeNum(v), "—", "Lifetime request count"})
	}
	sb.WriteString(mdTable(netRows))
	sb.WriteString("\n")

	// ── Databases & Collections ──
	if dbListJSON := dm["db_list"]; dbListJSON != "" {
		var dbs []dbEntry
		if err := json.Unmarshal([]byte(dbListJSON), &dbs); err == nil && len(dbs) > 0 {
			sb.WriteString("### Databases & Collections\n\n")
			for _, d := range dbs {
				if d.Name == "admin" || d.Name == "config" || d.Name == "local" {
					continue
				}
				sb.WriteString(fmt.Sprintf("#### %s  (%.0f MB, %d collections, %d indexes)\n\n",
					d.Name, d.SizeMB, d.Collections, d.Indexes))

				if len(d.Colls) > 0 {
					collRows := [][]string{{"Collection", "Size", "Docs", "Rd/s", "Wr/s", "R.Avg", "W.Avg", "Indexes", "Status"}}
					for _, c := range d.Colls {
						rdRate := "—"
						wrRate := "—"
						if c.ROpsRate > 0 {
							rdRate = fmt.Sprintf("%.1f", c.ROpsRate)
						}
						if c.WOpsRate > 0 {
							wrRate = fmt.Sprintf("%.1f", c.WOpsRate)
						}
						rAvg := "—"
						wAvg := "—"
						if c.RAvgUs > 0 {
							rAvg = fmtMicros(c.RAvgUs)
						}
						if c.WAvgUs > 0 {
							wAvg = fmtMicros(c.WAvgUs)
						}
						status := "OK"
						if c.Indexes <= 1 && c.Docs > 50000 && c.ROps > 100 {
							status = "**CRIT** — missing indexes"
							optScore -= 10
						} else if c.RAvgUs > 100000 {
							status = "**CRIT** — reads > 100ms"
							optScore -= 10
						} else if c.RAvgUs > 10000 {
							status = "WARN — reads > 10ms"
							optScore -= 3
						} else if c.WAvgUs > 50000 {
							status = "WARN — writes > 50ms"
							optScore -= 3
						}
						idxList := strings.Join(c.IdxNames, ", ")
						collRows = append(collRows, []string{
							c.Name, fmt.Sprintf("%.0f MB", c.SizeMB), fmtDocCount(c.Docs),
							rdRate, wrRate, rAvg, wAvg, idxList, status,
						})
					}
					sb.WriteString(mdTable(collRows))
					sb.WriteString("\n")
				}

				writeMongoIndexAnalysis(sb, d.Name, d.Colls)
			}
		}
	}

	// ── Client Connections ──
	if clientJSON := dm["client_connections"]; clientJSON != "" {
		type clientEntry struct {
			IP    string `json:"ip"`
			Count int    `json:"count"`
		}
		var clients []clientEntry
		if err := json.Unmarshal([]byte(clientJSON), &clients); err == nil && len(clients) > 0 {
			totalConns := 0
			for _, c := range clients {
				totalConns += c.Count
			}
			sb.WriteString(fmt.Sprintf("### Client Connections (%d total, %d sources)\n\n", totalConns, len(clients)))
			ccRows := [][]string{{"Client IP", "Connections", "Share", "Status", "Recommendation"}}
			for _, c := range clients {
				pct := float64(c.Count) / float64(totalConns) * 100
				status, rec := "OK", "Within best practice"
				if c.Count > 200 {
					status, rec = "**CRIT**", "**Reduce maxPoolSize to 10-20**"
				} else if c.Count > 100 {
					status, rec = "WARN", "High — set maxPoolSize: 20"
				} else if c.Count > 50 {
					status, rec = "INFO", "Monitor — typical pool is 10-50"
				}
				ccRows = append(ccRows, []string{c.IP, fmt.Sprintf("%d", c.Count), fmt.Sprintf("%.0f%%", pct), status, rec})
			}
			sb.WriteString(mdTable(ccRows))
			sb.WriteString("\n")

			if len(clients) > 0 {
				maxClient := clients[0]
				for _, c := range clients {
					if c.Count > maxClient.Count {
						maxClient = c
					}
				}
				if float64(maxClient.Count)/float64(totalConns)*100 > 50 {
					sb.WriteString(fmt.Sprintf("> **Imbalance detected:** %s holds %.0f%% of all connections.\n\n",
						maxClient.IP, float64(maxClient.Count)/float64(totalConns)*100))
				}
			}
		}
	}

	// ── Operation Breakdown ──
	if opJSON := dm["op_type_breakdown"]; opJSON != "" {
		type opEntry struct {
			Op    string `json:"op"`
			Count int    `json:"count"`
		}
		var ops []opEntry
		if err := json.Unmarshal([]byte(opJSON), &ops); err == nil && len(ops) > 0 {
			total := 0
			for _, o := range ops {
				total += o.Count
			}
			sb.WriteString(fmt.Sprintf("### Active Operation Breakdown (%d total)\n\n", total))
			obRows := [][]string{{"Operation", "Count", "Share", "Status"}}
			for _, o := range ops {
				pct := float64(o.Count) / float64(total) * 100
				status := "OK"
				if o.Op == "none" && o.Count > 100 {
					status = "WARN — idle connections"
				} else if pct > 50 && o.Op != "none" {
					status = fmt.Sprintf("Dominant (%s-heavy)", o.Op)
				}
				obRows = append(obRows, []string{o.Op, fmt.Sprintf("%d", o.Count), fmt.Sprintf("%.0f%%", pct), status})
			}
			sb.WriteString(mdTable(obRows))
			sb.WriteString("\n")
		}
	}

	// ── Optimization Score ──
	if optScore < 0 {
		optScore = 0
	}
	sb.WriteString("### Optimization Score\n\n")
	optLevel := "EXCELLENT"
	optDesc := "MongoDB is well-tuned. No significant issues detected."
	if optScore < 40 {
		optLevel = "CRITICAL"
		optDesc = "Significant performance issues. Immediate action required."
	} else if optScore < 60 {
		optLevel = "POOR"
		optDesc = "Multiple issues affecting performance. Review findings above."
	} else if optScore < 80 {
		optLevel = "FAIR"
		optDesc = "Some optimization opportunities. Address warnings when possible."
	} else if optScore < 95 {
		optLevel = "GOOD"
		optDesc = "Minor improvements possible."
	}
	sb.WriteString(fmt.Sprintf("**Score: %d/100 — %s**\n\n", optScore, optLevel))
	sb.WriteString(fmt.Sprintf("%s\n\n", optDesc))
	if len(optIssues) > 0 {
		sb.WriteString("**Key issues reducing score:**\n")
		for _, iss := range optIssues {
			sb.WriteString(fmt.Sprintf("- %s\n", iss))
		}
		sb.WriteString("\n")
	}
}

// writeMongoIndexAnalysis writes index findings for a database's collections.
func writeMongoIndexAnalysis(sb *strings.Builder, dbName string, colls []collEntry) {
	// Build sibling index map
	sibIdx := make(map[string]map[string]bool)
	for _, c := range colls {
		idxSet := make(map[string]bool)
		for _, idx := range c.IdxNames {
			if idx != "_id_" {
				idxSet[idx] = true
			}
		}
		sibIdx[c.Name] = idxSet
	}

	var findings []string
	seen := make(map[string]bool) // "collection|field" dedup key
	for _, c := range colls {
		if c.Indexes >= 2 || c.Docs <= 50000 || c.ROps <= 100 {
			continue
		}
		// Large collection with only _id index
		sev := "WARN"
		if c.ROpsRate > 1000 || c.Docs > 1000000 {
			sev = "CRIT"
		}

		foundSibling := false
		// Check siblings for missing indexes (deduplicate by collection+field)
		for sibName, siIdxSet := range sibIdx {
			if sibName == c.Name {
				continue
			}
			if !areSiblings(c.Name, sibName) {
				continue
			}
			for idx := range siIdxSet {
				if sibIdx[c.Name][idx] {
					continue
				}
				field := strings.TrimSuffix(idx, "_1")
				dedupKey := c.Name + "|" + field
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true
				foundSibling = true
				findings = append(findings, fmt.Sprintf(
					"- **[%s]** `%s.%s` — No `%s` index on %s docs. Every `%s` query scans entire collection.\n"+
						"  - Sibling `%s` has this index\n"+
						"  - **Fix:** `db.getSiblingDB(\"%s\").%s.createIndex({%s: 1})`\n"+
						"  - Safe to run in production (background build, no downtime)\n",
					sev, dbName, c.Name, field, fmtDocCount(c.Docs), field,
					sibName, dbName, c.Name, field))
			}
		}

		if !foundSibling {
			dedupKey := c.Name + "|_generic"
			if !seen[dedupKey] {
				seen[dedupKey] = true
				findings = append(findings, fmt.Sprintf(
					"- **[%s]** `%s.%s` — Only `_id` index on %s docs with %s reads.\n"+
						"  - **Fix:** Enable profiling: `db.setProfilingLevel(1, {slowms: 50})`\n"+
						"  - Then check `db.system.profile` for COLLSCAN queries\n",
					sev, dbName, c.Name, fmtDocCount(c.Docs), fmtLargeNum(fmt.Sprintf("%d", c.ROps))))
			}
		}
	}

	if len(findings) > 0 {
		sb.WriteString("**Index Issues:**\n\n")
		for _, f := range findings {
			sb.WriteString(f)
		}
		sb.WriteString("\n")
	}
}

// areSiblings checks if two collection names are variants (e.g., "Foo" and "Foo_New").
func areSiblings(a, b string) bool {
	if strings.HasSuffix(a, "_New") && strings.TrimSuffix(a, "_New") == b {
		return true
	}
	if strings.HasSuffix(b, "_New") && strings.TrimSuffix(b, "_New") == a {
		return true
	}
	baseA, baseB := a, b
	for _, suf := range []string{"_New", "_DAG2_New", "_DAG2"} {
		baseA = strings.TrimSuffix(baseA, suf)
		baseB = strings.TrimSuffix(baseB, suf)
	}
	return baseA == baseB && a != b
}

// fmtLargeNum formats a large number string with K/M/B suffix.
func fmtLargeNum(s string) string {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	switch {
	case v >= 1e12:
		return fmt.Sprintf("%.1fT", v/1e12)
	case v >= 1e9:
		return fmt.Sprintf("%.1fB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

// fmtBytes formats a byte count string to human-readable.
func fmtBytes(s string) string {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	switch {
	case v >= 1e15:
		return fmt.Sprintf("%.1f PB", v/1e15)
	case v >= 1e12:
		return fmt.Sprintf("%.1f TB", v/1e12)
	case v >= 1e9:
		return fmt.Sprintf("%.1f GB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1f MB", v/1e6)
	default:
		return fmt.Sprintf("%.0f B", v)
	}
}

// fmtMicros formats microseconds to human-readable latency.
func fmtMicros(us int64) string {
	if us >= 1000000 {
		return fmt.Sprintf("%.1fs", float64(us)/1e6)
	}
	if us >= 1000 {
		return fmt.Sprintf("%.1fms", float64(us)/1e3)
	}
	return fmt.Sprintf("%dus", us)
}

// fmtDocCount formats document count with suffix.
func fmtDocCount(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// mdTable builds a properly aligned Markdown table.
// First row is the header. All rows must have the same number of columns.
func mdTable(rows [][]string) string {
	if len(rows) < 1 {
		return ""
	}
	cols := len(rows[0])
	// Calculate max width per column
	widths := make([]int, cols)
	for _, row := range rows {
		for i := 0; i < cols && i < len(row); i++ {
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}
	// Minimum width 3 for separator
	for i := range widths {
		if widths[i] < 3 {
			widths[i] = 3
		}
	}

	var sb strings.Builder
	// Header row
	sb.WriteByte('|')
	for i, cell := range rows[0] {
		sb.WriteString(fmt.Sprintf(" %-*s |", widths[i], cell))
	}
	sb.WriteByte('\n')
	// Separator
	sb.WriteByte('|')
	for i := range rows[0] {
		sb.WriteString(strings.Repeat("-", widths[i]+2))
		sb.WriteByte('|')
	}
	sb.WriteByte('\n')
	// Data rows
	for _, row := range rows[1:] {
		sb.WriteByte('|')
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			sb.WriteString(fmt.Sprintf(" %-*s |", widths[i], cell))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// formatUptime converts seconds to a human-readable duration.
func formatUptime(sec int64) string {
	if sec <= 0 {
		return "—"
	}
	d := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh", d, h)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// appDoctorJSONReport for JSON output mode.
type appDoctorJSONReport struct {
	Timestamp string               `json:"timestamp"`
	Hostname  string               `json:"hostname"`
	Version   string               `json:"version"`
	Apps      []appDoctorJSONApp   `json:"applications"`
	Summary   appDoctorJSONSummary `json:"summary"`
}

type appDoctorJSONApp struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	AppType     string            `json:"app_type"`
	Version     string            `json:"version"`
	PID         int               `json:"pid"`
	Port        int               `json:"port"`
	Uptime      string            `json:"uptime"`
	HealthScore int               `json:"health_score"`
	HealthTrend string            `json:"health_trend"`
	Resources   appDoctorJSONRes  `json:"resources"`
	Deep        map[string]string `json:"deep_metrics,omitempty"`
	Findings    []appDoctorJSONF  `json:"findings"`
	Issues      []string          `json:"issues,omitempty"`
}

type appDoctorJSONRes struct {
	CPUAvg      float64 `json:"cpu_avg_pct"`
	CPUMax      float64 `json:"cpu_max_pct"`
	RSSMB       float64 `json:"rss_avg_mb"`
	RSSMaxMB    float64 `json:"rss_max_mb"`
	Connections int     `json:"connections_max"`
	FDs         int     `json:"fds_max"`
	Threads     float64 `json:"threads_avg"`
}

type appDoctorJSONF struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Problem  string `json:"problem"`
	Impact   string `json:"impact,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

type appDoctorJSONSummary struct {
	TotalApps int    `json:"total_apps"`
	Critical  int    `json:"critical"`
	Warnings  int    `json:"warnings"`
	Status    string `json:"status"`
}

func generateAppDoctorJSON(reports []appReport, hostname string, ts time.Time) ([]byte, error) {
	jr := appDoctorJSONReport{
		Timestamp: ts.Format(time.RFC3339),
		Hostname:  hostname,
		Version:   Version,
	}

	totalCrit := 0
	totalWarn := 0

	for _, r := range reports {
		app := appDoctorJSONApp{
			ID:          r.ID,
			DisplayName: r.DisplayName,
			AppType:     r.AppType,
			Version:     r.Version,
			PID:         r.PID,
			Port:        r.Port,
			Uptime:      formatUptime(r.UptimeSec),
			HealthScore: r.HealthScore,
			HealthTrend: r.HealthTrend,
			Deep:        r.Deep,
			Issues:      r.Issues,
			Resources: appDoctorJSONRes{
				CPUAvg:      r.AvgCPU,
				CPUMax:      r.MaxCPU,
				RSSMB:       r.AvgRSS,
				RSSMaxMB:    r.MaxRSS,
				Connections: r.MaxConns,
				FDs:         r.MaxFDs,
				Threads:     r.AvgThreads,
			},
		}
		for _, f := range r.Findings {
			app.Findings = append(app.Findings, appDoctorJSONF{
				Severity: f.severity,
				Category: f.category,
				Problem:  f.problem,
				Impact:   f.impact,
				Fix:      f.fix,
			})
			switch f.severity {
			case "CRIT":
				totalCrit++
			case "WARN":
				totalWarn++
			}
		}
		jr.Apps = append(jr.Apps, app)
	}

	status := "HEALTHY"
	if totalCrit > 0 {
		status = "CRITICAL"
	} else if totalWarn > 0 {
		status = "WARNING"
	}
	jr.Summary = appDoctorJSONSummary{
		TotalApps: len(reports),
		Critical:  totalCrit,
		Warnings:  totalWarn,
		Status:    status,
	}

	return json.MarshalIndent(jr, "", "  ")
}
