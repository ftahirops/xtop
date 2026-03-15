//go:build linux

package apps

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type haproxyModule struct{}

func NewHAProxyModule() AppModule { return &haproxyModule{} }

func (m *haproxyModule) Type() string        { return "haproxy" }
func (m *haproxyModule) DisplayName() string { return "HAProxy" }

func (m *haproxyModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm == "haproxy" && p.PPID <= 2 {
			port := findListeningPort(p.PID)
			apps = append(apps, DetectedApp{
				PID:     p.PID,
				Port:    port,
				Comm:    p.Comm,
				Cmdline: readProcCmdline(p.PID),
				Index:   len(apps),
			})
		}
	}
	return apps
}

func (m *haproxyModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "haproxy",
		DisplayName: "HAProxy",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process-level metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)

	inst.ConfigPath = findConfigFile([]string{
		"/etc/haproxy/haproxy.cfg",
		"/usr/local/etc/haproxy/haproxy.cfg",
	})

	// Count worker processes and sum worker RSS, threads, FDs, and find ports
	workerCount := 0
	workerRSS := 0.0
	workerThreads := 0
	workerFDs := 0
	var workerPIDs []int
	allPorts := make(map[int]bool)
	entries, _ := procEntries()
	for _, pid := range entries {
		if pid == app.PID {
			continue
		}
		ppid, pcomm := readPPIDComm(pid)
		if ppid == app.PID && pcomm == "haproxy" {
			workerCount++
			workerPIDs = append(workerPIDs, pid)
			workerRSS += readProcRSS(pid)
			workerThreads += readProcThreads(pid)
			workerFDs += readProcFDs(pid)

			// Workers bind the listening ports, not the master
			for _, p := range findAllListeningPorts(pid) {
				allPorts[p] = true
			}
			// Set inst.Port from first worker if not already set
			if inst.Port == 0 {
				wp := findListeningPort(pid)
				if wp > 0 {
					inst.Port = wp
					app.Port = wp
				}
			}
		}
	}
	inst.RSSMB += workerRSS
	inst.Threads += workerThreads
	inst.FDs += workerFDs
	inst.DeepMetrics["workers"] = fmt.Sprintf("%d", workerCount)
	if len(workerPIDs) > 0 {
		inst.DeepMetrics["worker_pid"] = fmt.Sprintf("%d", workerPIDs[0])
	}

	// Store all listening ports
	if len(allPorts) > 0 {
		var portStrs []string
		for p := range allPorts {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		sort.Strings(portStrs)
		inst.DeepMetrics["listen_ports"] = strings.Join(portStrs, ",")
	}

	// Count total connections across ALL listening ports
	totalConns := 0
	for p := range allPorts {
		totalConns += countTCPConnections(p)
	}
	inst.Connections = totalConns
	inst.DeepMetrics["total_connections"] = fmt.Sprintf("%d", totalConns)

	// Config analysis
	var cfgMaxConn int
	if inst.ConfigPath != "" {
		cfg := parseHAProxyConfig(inst.ConfigPath)
		if cfg.maxConn > 0 {
			inst.DeepMetrics["cfg_maxconn"] = fmt.Sprintf("%d", cfg.maxConn)
			cfgMaxConn = cfg.maxConn
		}
		if cfg.nbThread > 0 {
			inst.DeepMetrics["cfg_nbthread"] = fmt.Sprintf("%d", cfg.nbThread)
		}
		if cfg.nbProc > 0 {
			inst.DeepMetrics["cfg_nbproc"] = fmt.Sprintf("%d", cfg.nbProc)
		}
		if cfg.frontendCount > 0 {
			inst.DeepMetrics["cfg_frontends"] = fmt.Sprintf("%d", cfg.frontendCount)
		}
		if cfg.backendCount > 0 {
			inst.DeepMetrics["cfg_backends"] = fmt.Sprintf("%d", cfg.backendCount)
		}
		if cfg.defaultBackend != "" {
			inst.DeepMetrics["default_backend"] = cfg.defaultBackend
		}
		if cfg.statsEnabled {
			inst.DeepMetrics["cfg_stats"] = "enabled"
			if cfg.statsURI != "" {
				inst.DeepMetrics["cfg_stats_uri"] = cfg.statsURI
			}
		}

		// Config warnings
		var cfgWarnings []string
		if !cfg.hasHealthCheck {
			cfgWarnings = append(cfgWarnings, "No health checks configured (missing option httpchk/tcp-check)")
		}
		if cfg.singleServerBackends > 0 {
			cfgWarnings = append(cfgWarnings, fmt.Sprintf("%d backend(s) with only 1 server (no redundancy)", cfg.singleServerBackends))
		}
		for t := range cfg.missingTimeouts {
			cfgWarnings = append(cfgWarnings, fmt.Sprintf("Missing %s in config", t))
		}
		inst.DeepMetrics["config_warning_count"] = fmt.Sprintf("%d", len(cfgWarnings))
		for i, w := range cfgWarnings {
			inst.DeepMetrics[fmt.Sprintf("config_warning_%d", i)] = w
		}
	}

	// Tier 2: deep metrics via stats socket or HTTP
	socketPath := findHAProxySocket(inst.ConfigPath)
	inst.DeepMetrics["stats_socket"] = socketPath

	health := haproxyHealth{score: 100}
	gotStats := false

	if socketPath != "" {
		gotStats = collectHAProxySocketStats(&inst, socketPath, &health, cfgMaxConn)
	}

	// Fallback: try HTTP stats CSV if no socket or socket failed
	if !gotStats && app.Port > 0 {
		gotStats = collectHAProxyHTTPStats(&inst, app.Port, &health, cfgMaxConn)
	}

	if gotStats {
		inst.HasDeepMetrics = true
	}

	// CPU%: use idle_pct from "show info" (100 - idle_pct = approx CPU usage)
	if idleStr, ok := inst.DeepMetrics["idle_pct"]; ok {
		idle, err := strconv.ParseFloat(idleStr, 64)
		if err == nil {
			inst.CPUPct = 100.0 - idle
			if inst.CPUPct < 0 {
				inst.CPUPct = 0
			}
		}
	}

	// Clamp health score
	inst.HealthScore = health.score
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}
	inst.HealthIssues = health.issues

	return inst
}

// haproxyHealth tracks penalties and issues during collection.
type haproxyHealth struct {
	score  int
	issues []string
}

func (h *haproxyHealth) penalize(amount int, issue string) {
	h.score -= amount
	h.issues = append(h.issues, issue)
}

// haproxyConfig holds parsed config values.
type haproxyConfig struct {
	maxConn              int
	nbThread             int
	nbProc               int
	frontendCount        int
	backendCount         int
	statsEnabled         bool
	statsURI             string
	statsSockets         []string
	defaultBackend       string
	hasHealthCheck       bool            // any backend has option httpchk / tcp-check
	singleServerBackends int             // backends with only 1 server
	missingTimeouts      map[string]bool // track which critical timeouts are missing
}

// parseHAProxyConfig extracts key settings from haproxy.cfg.
func parseHAProxyConfig(path string) haproxyConfig {
	var cfg haproxyConfig
	cfg.missingTimeouts = map[string]bool{
		"timeout connect": true,
		"timeout server":  true,
		"timeout client":  true,
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg
	}
	defer f.Close()

	inGlobal := false
	currentBackendServers := 0
	inBackend := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Track sections
		if strings.HasPrefix(line, "global") {
			inGlobal = true
			inBackend = false
			continue
		}
		if len(line) > 0 && line[0] != '#' && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// New section — no longer in global
			if !strings.HasPrefix(line, "global") {
				inGlobal = false
			}
			// Leaving a backend section — count single-server backends
			if inBackend && currentBackendServers == 1 {
				cfg.singleServerBackends++
			}
			inBackend = false
			currentBackendServers = 0
		}

		// Count frontend/backend sections
		if strings.HasPrefix(line, "frontend ") {
			cfg.frontendCount++
		}
		if strings.HasPrefix(line, "backend ") {
			cfg.backendCount++
			inBackend = true
			currentBackendServers = 0
		}
		if strings.HasPrefix(line, "default_backend ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				cfg.defaultBackend = parts[1]
			}
		}

		// Count servers in current backend
		if inBackend && strings.HasPrefix(line, "server ") {
			currentBackendServers++
		}

		// Health check detection
		if line == "option httpchk" || strings.HasPrefix(line, "option httpchk ") ||
			line == "option tcp-check" || strings.HasPrefix(line, "option tcp-check ") {
			cfg.hasHealthCheck = true
		}

		// Timeout detection
		if strings.HasPrefix(line, "timeout connect") {
			delete(cfg.missingTimeouts, "timeout connect")
		}
		if strings.HasPrefix(line, "timeout server") {
			delete(cfg.missingTimeouts, "timeout server")
		}
		if strings.HasPrefix(line, "timeout client") {
			delete(cfg.missingTimeouts, "timeout client")
		}

		// Stats socket (usually in global)
		if strings.HasPrefix(line, "stats socket ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				cfg.statsSockets = append(cfg.statsSockets, parts[2])
			}
		}

		// Stats enable/uri (in listen/frontend stats sections)
		if line == "stats enable" {
			cfg.statsEnabled = true
		}
		if strings.HasPrefix(line, "stats uri ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				cfg.statsURI = parts[2]
				cfg.statsEnabled = true
			}
		}

		// Global settings
		if inGlobal {
			if strings.HasPrefix(line, "maxconn ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					cfg.maxConn, _ = strconv.Atoi(parts[1])
				}
			}
			if strings.HasPrefix(line, "nbthread ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					cfg.nbThread, _ = strconv.Atoi(parts[1])
				}
			}
			if strings.HasPrefix(line, "nbproc ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					cfg.nbProc, _ = strconv.Atoi(parts[1])
				}
			}
		}

		// maxconn can also appear in defaults/frontend — use global one primarily
		// but capture if we haven't found one yet
		if cfg.maxConn == 0 && strings.HasPrefix(line, "maxconn ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				cfg.maxConn, _ = strconv.Atoi(parts[1])
			}
		}
	}

	// Handle last backend section
	if inBackend && currentBackendServers == 1 {
		cfg.singleServerBackends++
	}

	return cfg
}

// findHAProxySocket finds the stats socket path from config or common locations.
func findHAProxySocket(confPath string) string {
	// First try parsing config
	if confPath != "" {
		cfg := parseHAProxyConfig(confPath)
		for _, sock := range cfg.statsSockets {
			if _, err := os.Stat(sock); err == nil {
				return sock
			}
		}
	}

	// Check common socket locations
	commonPaths := []string{
		"/run/haproxy/admin.sock",
		"/var/lib/haproxy/stats",
		"/var/run/haproxy.sock",
		"/var/run/haproxy/admin.sock",
		"/tmp/haproxy.sock",
	}
	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// haproxyShowStat sends "show stat" to the HAProxy unix socket and returns the CSV output.
func haproxyShowStat(socketPath string) (string, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "show stat\n")
	data, err := io.ReadAll(conn)
	return string(data), err
}

// haproxyShowInfo sends "show info" to the HAProxy unix socket and returns the output.
func haproxyShowInfo(socketPath string) (string, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "show info\n")
	data, err := io.ReadAll(conn)
	return string(data), err
}

// parseHAProxyInfo parses "show info" key-value output into a map.
func parseHAProxyInfo(raw string) map[string]string {
	info := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ": ")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+2:])
		info[key] = val
	}
	return info
}

// haproxyStatRow holds parsed fields from one CSV row of "show stat".
type haproxyStatRow struct {
	pxname  string // proxy name
	svname  string // FRONTEND, BACKEND, or server name
	scur    int64  // current sessions
	smax    int64  // max sessions
	slim    int64  // session limit
	stot    int64  // total sessions
	rate    int64  // session rate
	status  string // UP, DOWN, OPEN, MAINT, etc.
	mode    string // http, tcp, health
	ereq    int64  // request errors (frontend only)
	econ    int64  // connection errors
	eresp   int64  // response errors
	wretr   int64  // retries
	wredis  int64  // redispatches
	reqRate int64  // request rate (frontend)
	reqTot  int64  // total requests
	cliAbrt int64  // client aborts
	srvAbrt int64  // server aborts
	hrsp4xx int64  // 4xx responses
	hrsp5xx int64  // 5xx responses
	qcur    int64  // current queue
	qmax    int64  // max queue
	addr    string // server address (IP:port)
	bin     int64  // bytes in
	bout    int64  // bytes out
	hrsp2xx int64  // 2xx responses
	hrsp3xx int64  // 3xx responses
	rtime   int64  // avg response time (ms) - backend only
	ttime   int64  // avg total time (ms) - backend only
	dreq    int64  // denied requests
	dresp   int64  // denied responses
	qtime   int64  // avg queue time (ms) - backend only
	ctime   int64  // avg connect time (ms) - backend only
	lastchg     int64  // seconds since last status change
	checkStatus string // health check status (L4OK, L7OK, L7STS, etc.)
	checkCode   int64  // health check HTTP response code
	checkDur    int64  // health check duration (ms)
	lastChk     string // last health check description
}

// parseHAProxyStats parses "show stat" CSV output into rows.
func parseHAProxyStats(raw string) []haproxyStatRow {
	// Strip leading "# " from header if present
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "# ") {
		raw = raw[2:]
	}

	reader := csv.NewReader(strings.NewReader(raw))
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1 // variable fields

	header, err := reader.Read()
	if err != nil {
		return nil
	}

	// Build column index map
	colIdx := make(map[string]int)
	for i, col := range header {
		colIdx[strings.TrimSpace(col)] = i
	}

	var rows []haproxyStatRow
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		getStr := func(name string) string {
			if idx, ok := colIdx[name]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}
		getInt := func(name string) int64 {
			s := getStr(name)
			if s == "" {
				return 0
			}
			v, _ := strconv.ParseInt(s, 10, 64)
			return v
		}

		row := haproxyStatRow{
			pxname:  getStr("pxname"),
			svname:  getStr("svname"),
			scur:    getInt("scur"),
			smax:    getInt("smax"),
			slim:    getInt("slim"),
			stot:    getInt("stot"),
			rate:    getInt("rate"),
			status:  getStr("status"),
			mode:    getStr("mode"),
			ereq:    getInt("ereq"),
			econ:    getInt("econ"),
			eresp:   getInt("eresp"),
			wretr:   getInt("wretr"),
			wredis:  getInt("wredis"),
			reqRate: getInt("req_rate"),
			reqTot:  getInt("req_tot"),
			cliAbrt: getInt("cli_abrt"),
			srvAbrt: getInt("srv_abrt"),
			hrsp4xx: getInt("hrsp_4xx"),
			hrsp5xx: getInt("hrsp_5xx"),
			qcur:    getInt("qcur"),
			qmax:    getInt("qmax"),
			addr:    getStr("addr"),
			bin:     getInt("bin"),
			bout:    getInt("bout"),
			hrsp2xx: getInt("hrsp_2xx"),
			hrsp3xx: getInt("hrsp_3xx"),
			rtime:   getInt("rtime"),
			ttime:   getInt("ttime"),
			dreq:    getInt("dreq"),
			dresp:   getInt("dresp"),
			qtime:   getInt("qtime"),
			ctime:   getInt("ctime"),
			lastchg:     getInt("lastchg"),
			checkStatus: getStr("check_status"),
			checkCode:   getInt("check_code"),
			checkDur:    getInt("check_duration"),
			lastChk:     getStr("last_chk"),
		}
		rows = append(rows, row)
	}
	return rows
}

// backendSession tracks backend names by total sessions for top-N ranking.
type backendSession struct {
	name     string
	sessions int64
	rate     int64
}

// applyHAProxyInfoMetrics stores "show info" fields into DeepMetrics and returns parsed values.
func applyHAProxyInfoMetrics(inst *model.AppInstance, info map[string]string, health *haproxyHealth) {
	// Version
	if v, ok := info["Version"]; ok && v != "" {
		inst.Version = v
	}

	storeInfo := func(metricKey, infoKey string) {
		if v, ok := info[infoKey]; ok && v != "" {
			inst.DeepMetrics[metricKey] = v
		}
	}

	storeInfo("max_conn", "MaxConn")
	storeInfo("curr_conn", "CurrConns")
	storeInfo("cum_connections", "CumConns")
	storeInfo("cum_requests", "CumReq")
	storeInfo("max_sess_rate", "MaxSessRate")
	storeInfo("idle_pct", "Idle_pct")
	storeInfo("run_queue", "Run_queue")
	storeInfo("tasks", "Tasks")

	// Health: idle_pct
	if idleStr, ok := info["Idle_pct"]; ok {
		idle, err := strconv.ParseFloat(idleStr, 64)
		if err == nil && idle < 20 {
			health.penalize(15, fmt.Sprintf("HAProxy CPU near saturation (idle %.0f%%)", idle))
		}
	}

	// Health: connection usage vs maxconn
	if currStr, ok := info["CurrConns"]; ok {
		if maxStr, ok2 := info["MaxConn"]; ok2 {
			curr, _ := strconv.ParseInt(currStr, 10, 64)
			maxC, _ := strconv.ParseInt(maxStr, 10, 64)
			if maxC > 0 && curr > 0 {
				pct := float64(curr) / float64(maxC) * 100
				if pct > 90 {
					health.penalize(25, fmt.Sprintf("connection usage %.0f%% of maxconn", pct))
				} else if pct > 80 {
					health.penalize(15, fmt.Sprintf("connection usage %.0f%% of maxconn", pct))
				}
			}
		}
	}
}

// applyHAProxyStatMetrics aggregates "show stat" rows into DeepMetrics and health.
func applyHAProxyStatMetrics(inst *model.AppInstance, rows []haproxyStatRow, health *haproxyHealth, cfgMaxConn int) {
	var (
		frontendCount  int
		backendCount   int
		serversTotal   int
		serversUp      int
		serversDown    int
		totalSessions  int64
		currentSess    int64
		sessionRate    int64
		requestRate    int64
		connErrors     int64
		feConnErrors   int64
		beConnErrors   int64
		srvConnErrors  int64
		respErrors     int64
		retries        int64
		http5xx        int64
		http4xx        int64
		clientAborts   int64
		serverAborts   int64
		queueCurrent   int64
		queueMax       int64
		totalReqs      int64
		bytesIn        int64
		bytesOut       int64
		feReqTot       int64 // frontend total requests (incoming)
		beReqTot       int64 // backend total requests (outgoing)
		feReqRate      int64 // frontend request rate
		beReqRate      int64 // backend session rate (used as req rate proxy)
		fe2xx, fe3xx   int64 // frontend 2xx/3xx
		be2xx, be3xx   int64 // backend 2xx/3xx
		feHrsp4xx      int64
		feHrsp5xx      int64
		feEreq         int64
		totalDreq      int64
		totalDresp     int64
		backendSess    []backendSession
	)

	for _, r := range rows {
		switch r.svname {
		case "FRONTEND":
			frontendCount++
			totalSessions += r.stot
			currentSess += r.scur
			sessionRate += r.rate
			requestRate += r.reqRate
			feReqRate += r.reqRate
			feReqTot += r.reqTot
			totalReqs += r.reqTot
			connErrors += r.econ
			feConnErrors += r.econ
			respErrors += r.eresp
			bytesIn += r.bin
			bytesOut += r.bout
			feHrsp4xx += r.hrsp4xx
			feHrsp5xx += r.hrsp5xx
			feEreq += r.ereq
			fe2xx += r.hrsp2xx
			fe3xx += r.hrsp3xx
			totalDreq += r.dreq
			totalDresp += r.dresp
		case "BACKEND":
			backendCount++
			connErrors += r.econ
			beConnErrors += r.econ
			respErrors += r.eresp
			retries += r.wretr
			http5xx += r.hrsp5xx
			http4xx += r.hrsp4xx
			clientAborts += r.cliAbrt
			serverAborts += r.srvAbrt
			queueCurrent += r.qcur
			beReqTot += r.reqTot
			// reqRate is often 0 for backends; use session rate as proxy
			if r.reqRate > 0 {
				beReqRate += r.reqRate
			} else {
				beReqRate += r.rate
			}
			be2xx += r.hrsp2xx
			be3xx += r.hrsp3xx
			totalDreq += r.dreq
			totalDresp += r.dresp
			if r.qmax > queueMax {
				queueMax = r.qmax
			}
			backendSess = append(backendSess, backendSession{
				name:     r.pxname,
				sessions: r.stot,
				rate:     r.rate,
			})
		default:
			// Individual server
			serversTotal++
			st := strings.ToUpper(r.status)
			if st == "UP" {
				serversUp++
			} else if st == "DOWN" || st == "MAINT" {
				serversDown++
			}
			connErrors += r.econ
			srvConnErrors += r.econ
			respErrors += r.eresp
			retries += r.wretr
			http5xx += r.hrsp5xx
			http4xx += r.hrsp4xx
			clientAborts += r.cliAbrt
			serverAborts += r.srvAbrt
		}
	}

	// Store deep metrics
	inst.DeepMetrics["frontends"] = fmt.Sprintf("%d", frontendCount)
	inst.DeepMetrics["backends"] = fmt.Sprintf("%d", backendCount)
	inst.DeepMetrics["servers_total"] = fmt.Sprintf("%d", serversTotal)
	inst.DeepMetrics["servers_up"] = fmt.Sprintf("%d", serversUp)
	inst.DeepMetrics["servers_down"] = fmt.Sprintf("%d", serversDown)
	inst.DeepMetrics["total_sessions"] = fmt.Sprintf("%d", totalSessions)
	inst.DeepMetrics["current_sessions"] = fmt.Sprintf("%d", currentSess)
	inst.DeepMetrics["session_rate"] = fmt.Sprintf("%d", sessionRate)
	inst.DeepMetrics["request_rate"] = fmt.Sprintf("%d", requestRate)
	inst.DeepMetrics["connection_errors"] = fmt.Sprintf("%d", connErrors)
	inst.DeepMetrics["fe_conn_errors"] = fmt.Sprintf("%d", feConnErrors)
	inst.DeepMetrics["be_conn_errors"] = fmt.Sprintf("%d", beConnErrors)
	inst.DeepMetrics["srv_conn_errors"] = fmt.Sprintf("%d", srvConnErrors)
	inst.DeepMetrics["response_errors"] = fmt.Sprintf("%d", respErrors)
	inst.DeepMetrics["retries"] = fmt.Sprintf("%d", retries)
	inst.DeepMetrics["http_5xx"] = fmt.Sprintf("%d", http5xx)
	inst.DeepMetrics["http_4xx"] = fmt.Sprintf("%d", http4xx)
	inst.DeepMetrics["client_aborts"] = fmt.Sprintf("%d", clientAborts)
	inst.DeepMetrics["server_aborts"] = fmt.Sprintf("%d", serverAborts)
	inst.DeepMetrics["queue_current"] = fmt.Sprintf("%d", queueCurrent)
	inst.DeepMetrics["queue_max"] = fmt.Sprintf("%d", queueMax)
	inst.DeepMetrics["bytes_in"] = fmt.Sprintf("%d", bytesIn)
	inst.DeepMetrics["bytes_out"] = fmt.Sprintf("%d", bytesOut)
	inst.DeepMetrics["total_requests"] = fmt.Sprintf("%d", totalReqs)
	inst.DeepMetrics["total_dreq"] = fmt.Sprintf("%d", totalDreq)
	inst.DeepMetrics["total_dresp"] = fmt.Sprintf("%d", totalDresp)
	inst.DeepMetrics["fe_req_rate"] = fmt.Sprintf("%d", feReqRate)
	inst.DeepMetrics["be_req_rate"] = fmt.Sprintf("%d", beReqRate)
	inst.DeepMetrics["fe_req_total"] = fmt.Sprintf("%d", feReqTot)
	inst.DeepMetrics["be_req_total"] = fmt.Sprintf("%d", beReqTot)
	inst.DeepMetrics["fe_2xx"] = fmt.Sprintf("%d", fe2xx)
	inst.DeepMetrics["fe_3xx"] = fmt.Sprintf("%d", fe3xx)
	inst.DeepMetrics["fe_4xx"] = fmt.Sprintf("%d", feHrsp4xx)
	inst.DeepMetrics["fe_5xx"] = fmt.Sprintf("%d", feHrsp5xx)
	inst.DeepMetrics["be_2xx"] = fmt.Sprintf("%d", be2xx)
	inst.DeepMetrics["be_3xx"] = fmt.Sprintf("%d", be3xx)
	inst.DeepMetrics["fe_ereq"] = fmt.Sprintf("%d", feEreq)
	// Error rate percentages
	if feReqTot > 0 {
		inst.DeepMetrics["fe_5xx_pct"] = fmt.Sprintf("%.2f", float64(feHrsp5xx)/float64(feReqTot)*100)
		inst.DeepMetrics["fe_4xx_pct"] = fmt.Sprintf("%.2f", float64(feHrsp4xx)/float64(feReqTot)*100)
		inst.DeepMetrics["fe_2xx_pct"] = fmt.Sprintf("%.2f", float64(fe2xx)/float64(feReqTot)*100)
	}
	if totalReqs > 0 {
		inst.DeepMetrics["err_5xx_pct"] = fmt.Sprintf("%.2f", float64(http5xx)/float64(totalReqs)*100)
		inst.DeepMetrics["err_4xx_pct"] = fmt.Sprintf("%.2f", float64(http4xx)/float64(totalReqs)*100)
		inst.DeepMetrics["conn_err_pct"] = fmt.Sprintf("%.2f", float64(connErrors)/float64(totalReqs)*100)
		inst.DeepMetrics["retry_pct"] = fmt.Sprintf("%.2f", float64(retries)/float64(totalReqs)*100)
	}

	// Top 3 backends by sessions
	if len(backendSess) > 0 {
		sort.Slice(backendSess, func(i, j int) bool {
			return backendSess[i].sessions > backendSess[j].sessions
		})
		var top []string
		for i := 0; i < len(backendSess) && i < 3; i++ {
			top = append(top, fmt.Sprintf("%s(%s sess, %d/s)", backendSess[i].name, formatCount(backendSess[i].sessions), backendSess[i].rate))
		}
		inst.DeepMetrics["top_backends"] = strings.Join(top, " ")
	}

	// Proxy type analysis: HTTP vs TCP, per-frontend/backend details
	httpFrontends := 0
	tcpFrontends := 0
	httpBackends := 0
	tcpBackends := 0
	type proxyDetail struct {
		name    string
		mode    string
		servers []string
	}
	proxyMap := make(map[string]*proxyDetail) // keyed by pxname

	for _, r := range rows {
		if r.svname == "FRONTEND" {
			if r.mode == "http" {
				httpFrontends++
			} else if r.mode == "tcp" {
				tcpFrontends++
			}
			if _, ok := proxyMap[r.pxname]; !ok {
				proxyMap[r.pxname] = &proxyDetail{name: r.pxname, mode: r.mode}
			}
		} else if r.svname == "BACKEND" {
			if r.mode == "http" {
				httpBackends++
			} else if r.mode == "tcp" {
				tcpBackends++
			}
		} else if r.svname != "" {
			// Individual server — collect target addresses
			if pd, ok := proxyMap[r.pxname]; ok && r.addr != "" {
				pd.servers = append(pd.servers, r.addr)
			} else if r.addr != "" {
				if _, ok := proxyMap[r.pxname]; !ok {
					proxyMap[r.pxname] = &proxyDetail{name: r.pxname, mode: r.mode}
				}
				proxyMap[r.pxname].servers = append(proxyMap[r.pxname].servers, r.addr)
			}
		}
	}

	inst.DeepMetrics["http_frontends"] = fmt.Sprintf("%d", httpFrontends)
	inst.DeepMetrics["tcp_frontends"] = fmt.Sprintf("%d", tcpFrontends)
	inst.DeepMetrics["http_backends"] = fmt.Sprintf("%d", httpBackends)
	inst.DeepMetrics["tcp_backends"] = fmt.Sprintf("%d", tcpBackends)

	// Determine proxy role: forward vs reverse proxy
	// Forward proxy: many backends with 1 server each, diverse external IPs
	// Reverse proxy: few backends with multiple servers (load balancing), often private IPs
	proxyRole := "HTTP reverse proxy"
	if tcpFrontends > 0 && httpFrontends == 0 {
		proxyRole = "TCP proxy"
	} else if tcpFrontends > 0 && httpFrontends > 0 {
		proxyRole = "HTTP + TCP proxy"
	} else if httpBackends > 0 {
		// Count backends with single server vs multi-server (load balancing)
		singleServerBackends := 0
		publicIPs := 0
		for _, pd := range proxyMap {
			if len(pd.servers) == 1 {
				singleServerBackends++
			}
			for _, addr := range pd.servers {
				if !isPrivateAddr(addr) {
					publicIPs++
				}
			}
		}
		// Forward proxy heuristic: many unique backends each with 1 server,
		// and backends >> frontends, with mostly public IPs
		totalBackendEntries := len(proxyMap)
		if totalBackendEntries > 0 && httpFrontends > 0 {
			singleRatio := float64(singleServerBackends) / float64(totalBackendEntries)
			if singleRatio > 0.6 && totalBackendEntries > httpFrontends*3 && publicIPs > 0 {
				proxyRole = "HTTP forward proxy"
			}
		}
	}
	inst.DeepMetrics["proxy_role"] = proxyRole

	// Build proxy map summary: "frontend_name(mode) → server1, server2"
	var proxyLines []string
	for _, pd := range proxyMap {
		if len(pd.servers) == 0 {
			continue
		}
		srvList := pd.servers
		if len(srvList) > 3 {
			srvList = append(srvList[:3], fmt.Sprintf("+%d more", len(pd.servers)-3))
		}
		proxyLines = append(proxyLines, fmt.Sprintf("%s(%s) -> %s", pd.name, pd.mode, strings.Join(srvList, ", ")))
	}
	if len(proxyLines) > 5 {
		proxyLines = proxyLines[:5]
	}
	inst.DeepMetrics["proxy_map"] = strings.Join(proxyLines, "; ")

	// Health scoring from stats
	if serversDown > 0 {
		penalty := serversDown * 15
		if penalty > 30 {
			penalty = 30
		}
		health.penalize(penalty, fmt.Sprintf("%d backend server(s) DOWN", serversDown))
	}

	// Connection usage vs cfgMaxConn (if show info didn't already provide it)
	if cfgMaxConn > 0 {
		if _, exists := inst.DeepMetrics["max_conn"]; !exists {
			inst.DeepMetrics["max_conn"] = fmt.Sprintf("%d", cfgMaxConn)
		}
		if _, exists := inst.DeepMetrics["curr_conn"]; !exists && currentSess > 0 {
			pct := float64(currentSess) / float64(cfgMaxConn) * 100
			if pct > 90 {
				health.penalize(25, fmt.Sprintf("session usage %.0f%% of maxconn", pct))
			} else if pct > 80 {
				health.penalize(15, fmt.Sprintf("session usage %.0f%% of maxconn", pct))
			}
		}
	}

	if queueCurrent > 10 {
		health.penalize(20, fmt.Sprintf("requests queuing (%d) — backends overloaded", queueCurrent))
	} else if queueCurrent > 0 {
		health.penalize(10, "requests queuing — backends overloaded")
	}

	if totalReqs > 0 && http5xx > 0 {
		errPct := float64(http5xx) / float64(totalReqs) * 100
		if errPct > 1 {
			health.penalize(15, fmt.Sprintf("high HTTP 5xx rate (%.1f%%)", errPct))
		}
	}

	if respErrors > 0 {
		health.penalize(5, fmt.Sprintf("%d response errors", respErrors))
	}

	if connErrors > 100 {
		health.penalize(10, fmt.Sprintf("%d connection errors", connErrors))
	}

	if retries > 100 {
		health.penalize(10, fmt.Sprintf("%d retries", retries))
	}

	if clientAborts > 0 && serverAborts > 0 && clientAborts > serverAborts*2 {
		health.penalize(5, "high client abort rate — slow responses")
	}

	// ── Per-backend detail ──────────────────────────────────────────────
	type backendDetail struct {
		name         string
		status       string
		sessions     int64
		sessRate     int64 // session rate (current req/s)
		reqTot       int64 // total requests
		hrsp5xx      int64
		hrsp4xx      int64
		hrsp2xx      int64
		econ         int64
		eresp        int64
		retries      int64
		cliAbrt      int64
		srvAbrt      int64
		qcur         int64
		bin          int64
		bout         int64
		rtime        int64 // avg response time ms
		ttime        int64 // avg total time ms
		qtime        int64 // avg queue time ms
		ctime        int64 // avg connect time ms
		dreq         int64 // denied requests
		dresp        int64 // denied responses
		wredis       int64 // redispatches
		smax         int64 // max sessions
		scur         int64 // current sessions
		stot         int64 // total sessions
		qmax         int64 // max queue
		lastchg      int64 // seconds since last status change
		checkStatus  string // health check status per server
		checkCode    int64
		checkDur     int64
		lastChk      string
		serversUp    int
		serversDown  int
		serversTotal int
		serverAddr   string // first server address
		errPct       float64
	}

	// Track recently changed servers (lastchg < 3600 = changed in last hour)
	type serverChange struct {
		backend string
		server  string
		status  string
		lastchg int64 // seconds
		addr    string
	}
	var recentChanges []serverChange
	for _, r := range rows {
		if r.svname == "FRONTEND" || r.svname == "BACKEND" {
			continue
		}
		if r.lastchg > 0 && r.lastchg < 3600 {
			recentChanges = append(recentChanges, serverChange{
				backend: r.pxname,
				server:  r.svname,
				status:  r.status,
				lastchg: r.lastchg,
				addr:    r.addr,
			})
		}
	}
	// Sort by most recent change first
	sort.Slice(recentChanges, func(i, j int) bool { return recentChanges[i].lastchg < recentChanges[j].lastchg })
	chgCount := len(recentChanges)
	if chgCount > 5 {
		chgCount = 5
	}
	inst.DeepMetrics["recent_change_count"] = fmt.Sprintf("%d", chgCount)
	for i := 0; i < chgCount; i++ {
		sc := recentChanges[i]
		pfx := fmt.Sprintf("recent_change_%d_", i)
		inst.DeepMetrics[pfx+"backend"] = sc.backend
		inst.DeepMetrics[pfx+"server"] = sc.server
		inst.DeepMetrics[pfx+"status"] = sc.status
		inst.DeepMetrics[pfx+"lastchg"] = fmt.Sprintf("%d", sc.lastchg)
		inst.DeepMetrics[pfx+"addr"] = sc.addr
	}

	// Collect all backend rows
	var allBackends []backendDetail
	for _, r := range rows {
		if r.svname != "BACKEND" {
			continue
		}
		bd := backendDetail{
			name:     r.pxname,
			status:   r.status,
			sessions: r.stot,
			sessRate: r.rate,
			reqTot:   r.reqTot,
			hrsp5xx:  r.hrsp5xx,
			hrsp4xx:  r.hrsp4xx,
			hrsp2xx:  r.hrsp2xx,
			econ:     r.econ,
			eresp:    r.eresp,
			retries:  r.wretr,
			cliAbrt:  r.cliAbrt,
			srvAbrt:  r.srvAbrt,
			qcur:     r.qcur,
			bin:      r.bin,
			bout:     r.bout,
			rtime:    r.rtime,
			ttime:    r.ttime,
			qtime:    r.qtime,
			ctime:    r.ctime,
			dreq:     r.dreq,
			dresp:    r.dresp,
			wredis:   r.wredis,
			smax:     r.smax,
			scur:     r.scur,
			stot:     r.stot,
			qmax:     r.qmax,
			lastchg:  r.lastchg,
		}
		if bd.reqTot > 0 {
			bd.errPct = float64(bd.hrsp5xx+bd.econ) / float64(bd.reqTot) * 100
		}
		// Count servers, get first server address, and aggregate health check info
		checksEnabled := 0
		checksOK := 0
		checksFailed := 0
		var worstCheck string
		var worstCheckCode int64
		for _, sr := range rows {
			if sr.svname == "FRONTEND" || sr.svname == "BACKEND" {
				continue
			}
			if sr.pxname == r.pxname {
				bd.serversTotal++
				st := strings.ToUpper(sr.status)
				if st == "UP" {
					bd.serversUp++
				} else if st == "DOWN" || st == "MAINT" {
					bd.serversDown++
				}
				if bd.serverAddr == "" && sr.addr != "" {
					bd.serverAddr = sr.addr
				}
				// Health check aggregation
				if sr.checkStatus != "" && sr.checkStatus != "INI" && sr.checkStatus != "UNK" {
					checksEnabled++
					if sr.checkStatus == "L4OK" || sr.checkStatus == "L7OK" || sr.checkStatus == "L7OKC" || sr.checkStatus == "L6OK" {
						checksOK++
					} else {
						checksFailed++
						if worstCheck == "" {
							worstCheck = sr.checkStatus
							worstCheckCode = sr.checkCode
						}
					}
					if bd.checkDur < sr.checkDur {
						bd.checkDur = sr.checkDur
					}
				}
			}
		}
		if checksEnabled > 0 {
			bd.checkStatus = fmt.Sprintf("%d/%d OK", checksOK, checksEnabled)
			if checksFailed > 0 {
				bd.checkStatus = fmt.Sprintf("%d/%d OK, %d failing (%s", checksOK, checksEnabled, checksFailed, worstCheck)
				if worstCheckCode > 0 {
					bd.checkStatus += fmt.Sprintf(" HTTP %d", worstCheckCode)
				}
				bd.checkStatus += ")"
				bd.checkCode = worstCheckCode
			}
		} else {
			bd.checkStatus = "disabled"
		}
		bd.lastChk = fmt.Sprintf("%d", checksEnabled)
		allBackends = append(allBackends, bd)
	}

	// Sort by session rate (highest traffic first) for display
	sort.Slice(allBackends, func(i, j int) bool {
		return allBackends[i].sessRate > allBackends[j].sessRate
	})

	// Store top 15 by traffic
	beCount := len(allBackends)
	if beCount > 15 {
		beCount = 15
	}
	inst.DeepMetrics["be_detail_count"] = fmt.Sprintf("%d", beCount)

	for i := 0; i < beCount; i++ {
		bd := allBackends[i]
		pfx := fmt.Sprintf("be_detail_%d_", i)
		inst.DeepMetrics[pfx+"name"] = bd.name
		inst.DeepMetrics[pfx+"status"] = bd.status
		inst.DeepMetrics[pfx+"sessions"] = fmt.Sprintf("%d", bd.sessions)
		inst.DeepMetrics[pfx+"sess_rate"] = fmt.Sprintf("%d", bd.sessRate)
		inst.DeepMetrics[pfx+"req_total"] = fmt.Sprintf("%d", bd.reqTot)
		inst.DeepMetrics[pfx+"5xx"] = fmt.Sprintf("%d", bd.hrsp5xx)
		inst.DeepMetrics[pfx+"4xx"] = fmt.Sprintf("%d", bd.hrsp4xx)
		inst.DeepMetrics[pfx+"econ"] = fmt.Sprintf("%d", bd.econ)
		inst.DeepMetrics[pfx+"retries"] = fmt.Sprintf("%d", bd.retries)
		inst.DeepMetrics[pfx+"cli_abrt"] = fmt.Sprintf("%d", bd.cliAbrt)
		inst.DeepMetrics[pfx+"srv_abrt"] = fmt.Sprintf("%d", bd.srvAbrt)
		inst.DeepMetrics[pfx+"qcur"] = fmt.Sprintf("%d", bd.qcur)
		inst.DeepMetrics[pfx+"servers_up"] = fmt.Sprintf("%d", bd.serversUp)
		inst.DeepMetrics[pfx+"servers_down"] = fmt.Sprintf("%d", bd.serversDown)
		inst.DeepMetrics[pfx+"servers_total"] = fmt.Sprintf("%d", bd.serversTotal)
		inst.DeepMetrics[pfx+"addr"] = bd.serverAddr
		inst.DeepMetrics[pfx+"bin"] = fmt.Sprintf("%d", bd.bin)
		inst.DeepMetrics[pfx+"bout"] = fmt.Sprintf("%d", bd.bout)
		if bd.errPct > 0 {
			inst.DeepMetrics[pfx+"err_pct"] = fmt.Sprintf("%.2f", bd.errPct)
		}
		inst.DeepMetrics[pfx+"rtime"] = fmt.Sprintf("%d", bd.rtime)
		inst.DeepMetrics[pfx+"ttime"] = fmt.Sprintf("%d", bd.ttime)
		inst.DeepMetrics[pfx+"qtime"] = fmt.Sprintf("%d", bd.qtime)
		inst.DeepMetrics[pfx+"ctime"] = fmt.Sprintf("%d", bd.ctime)
		inst.DeepMetrics[pfx+"dreq"] = fmt.Sprintf("%d", bd.dreq)
		inst.DeepMetrics[pfx+"dresp"] = fmt.Sprintf("%d", bd.dresp)
		inst.DeepMetrics[pfx+"wredis"] = fmt.Sprintf("%d", bd.wredis)
		inst.DeepMetrics[pfx+"smax"] = fmt.Sprintf("%d", bd.smax)
		inst.DeepMetrics[pfx+"scur"] = fmt.Sprintf("%d", bd.scur)
		inst.DeepMetrics[pfx+"qmax"] = fmt.Sprintf("%d", bd.qmax)
		inst.DeepMetrics[pfx+"check_status"] = bd.checkStatus
		inst.DeepMetrics[pfx+"check_dur"] = fmt.Sprintf("%d", bd.checkDur)
		if bd.stot > 0 {
			inst.DeepMetrics[pfx+"retry_pct"] = fmt.Sprintf("%.2f", float64(bd.retries)/float64(bd.stot)*100)
		}

		// Per-backend health assessment
		beHealth := "HEALTHY"
		if bd.serversDown > 0 {
			beHealth = "DEGRADED"
		}
		if bd.errPct > 5 {
			beHealth = "CRITICAL"
		} else if bd.errPct > 1 {
			beHealth = "DEGRADED"
		}
		if bd.cliAbrt > 1000 && bd.reqTot > 0 && float64(bd.cliAbrt)/float64(bd.reqTot)*100 > 1 {
			if beHealth != "CRITICAL" {
				beHealth = "SLOW"
			}
		}
		if bd.rtime > 5000 {
			if beHealth != "CRITICAL" {
				beHealth = "SLOW"
			}
		} else if bd.rtime > 2000 && beHealth == "HEALTHY" {
			beHealth = "DEGRADED"
		}
		if strings.ToUpper(bd.status) == "DOWN" {
			beHealth = "DOWN"
		}
		inst.DeepMetrics[pfx+"health"] = beHealth
	}

	// ── Top 3 slowest backends by response time ─────────────────────────
	sort.Slice(allBackends, func(i, j int) bool { return allBackends[i].rtime > allBackends[j].rtime })
	slowCount := len(allBackends)
	if slowCount > 3 {
		slowCount = 3
	}
	for i := 0; i < slowCount; i++ {
		if allBackends[i].rtime == 0 {
			slowCount = i
			break
		}
		pfx := fmt.Sprintf("slow_be_%d_", i)
		inst.DeepMetrics[pfx+"name"] = allBackends[i].name
		inst.DeepMetrics[pfx+"rtime"] = fmt.Sprintf("%d", allBackends[i].rtime)
		inst.DeepMetrics[pfx+"ttime"] = fmt.Sprintf("%d", allBackends[i].ttime)
		inst.DeepMetrics[pfx+"qtime"] = fmt.Sprintf("%d", allBackends[i].qtime)
		inst.DeepMetrics[pfx+"ctime"] = fmt.Sprintf("%d", allBackends[i].ctime)
		inst.DeepMetrics[pfx+"addr"] = allBackends[i].serverAddr
	}
	inst.DeepMetrics["slow_be_count"] = fmt.Sprintf("%d", slowCount)

	// ── Deep RCA: per-backend blame analysis ────────────────────────────

	// Sort backends by 5xx for blame
	sort.Slice(allBackends, func(i, j int) bool {
		return allBackends[i].hrsp5xx > allBackends[j].hrsp5xx
	})

	// Build per-backend RCA lines (top 5 problematic backends)
	var rcaLines []string
	for i := 0; i < len(allBackends) && i < 5; i++ {
		bd := allBackends[i]
		totalErr := bd.hrsp5xx + bd.econ + bd.eresp
		if totalErr == 0 {
			break
		}
		line := fmt.Sprintf("%s [%s]", bd.name, bd.serverAddr)

		// Determine fault side
		if bd.econ > 0 && bd.hrsp5xx == 0 {
			// Connection errors but no 5xx = can't reach the supplier
			line += fmt.Sprintf(" — %s conn errors: supplier endpoint unreachable (DNS/network/firewall or endpoint down)", formatCount(bd.econ))
		} else if bd.hrsp5xx > 0 && bd.econ == 0 {
			// 5xx but no conn errors = supplier is responding but with errors
			errRate := float64(0)
			if bd.reqTot > 0 {
				errRate = float64(bd.hrsp5xx) / float64(bd.reqTot) * 100
			}
			line += fmt.Sprintf(" — %s 5xx (%.1f%% of %s reqs): supplier returning errors (overloaded/buggy/rate-limited)",
				formatCount(bd.hrsp5xx), errRate, formatCount(bd.reqTot))
		} else if bd.econ > 0 && bd.hrsp5xx > 0 {
			// Both = supplier intermittently failing
			line += fmt.Sprintf(" — %s 5xx + %s conn errors: supplier unstable (intermittent failures, possible overload)",
				formatCount(bd.hrsp5xx), formatCount(bd.econ))
		}

		// Abort analysis
		if bd.cliAbrt > 100 {
			line += fmt.Sprintf(". Client aborts: %s (supplier too slow, clients timing out)", formatCount(bd.cliAbrt))
		}
		if bd.retries > 100 {
			line += fmt.Sprintf(". Retries: %s (connection instability)", formatCount(bd.retries))
		}

		rcaLines = append(rcaLines, line)
	}

	// Store RCA
	if len(rcaLines) > 0 {
		inst.DeepMetrics["rca_backend_count"] = fmt.Sprintf("%d", len(rcaLines))
		for i, line := range rcaLines {
			inst.DeepMetrics[fmt.Sprintf("rca_backend_%d", i)] = line
		}
	}

	// Overall summary
	if http5xx > 0 && totalReqs > 0 {
		pct := float64(http5xx) / float64(totalReqs) * 100
		topName := ""
		if len(allBackends) > 0 && allBackends[0].hrsp5xx > 0 {
			topName = allBackends[0].name
		}
		inst.DeepMetrics["rca_summary"] = fmt.Sprintf("%.2f%% error rate (%s 5xx) — top offender: %s. Supplier-side failures (upstream returning errors/timeouts)",
			pct, formatCount(http5xx), topName)
	} else if connErrors > 100 {
		inst.DeepMetrics["rca_summary"] = fmt.Sprintf("%s connection errors — backends unreachable (DNS/network/endpoint down)",
			formatCount(connErrors))
	} else if queueCurrent > 10 {
		inst.DeepMetrics["rca_summary"] = fmt.Sprintf("Backend capacity exhausted — %d requests queued", queueCurrent)
	} else if serversDown > 0 {
		inst.DeepMetrics["rca_summary"] = fmt.Sprintf("%d backend server(s) DOWN", serversDown)
	} else if clientAborts > 1000 {
		inst.DeepMetrics["rca_summary"] = fmt.Sprintf("%s client aborts — backends responding too slowly, clients giving up",
			formatCount(clientAborts))
	} else {
		inst.DeepMetrics["rca_summary"] = "No significant issues detected"
	}

	// Abort RCA
	if clientAborts+serverAborts > 0 {
		suggestion := ""
		if serverAborts > 0 && clientAborts > serverAborts*10 {
			suggestion = "Clients timing out waiting for slow supplier responses. Consider increasing client timeout or optimizing slow backends."
		} else if serverAborts > clientAborts {
			suggestion = "Suppliers dropping connections. Check supplier health and network stability."
		} else {
			suggestion = "Mix of client timeouts and supplier drops. Review timeout settings and backend health."
		}
		inst.DeepMetrics["rca_abort_analysis"] = fmt.Sprintf(
			"Client aborts: %s (clients gave up waiting). Server aborts: %s (backends dropped mid-response). %s",
			formatCount(clientAborts), formatCount(serverAborts), suggestion)
	}

	// ── Per-frontend detail ─────────────────────────────────────────────
	type frontendDetail struct {
		name    string
		mode    string
		scur    int64
		stot    int64
		rate    int64
		reqRate int64
		bin     int64
		bout    int64
		hrsp2xx int64
		hrsp3xx int64
		hrsp4xx int64
		hrsp5xx int64
		ereq    int64
		econ    int64
		eresp   int64
	}
	var feDetails []frontendDetail
	for _, r := range rows {
		if r.svname != "FRONTEND" {
			continue
		}
		feDetails = append(feDetails, frontendDetail{
			name: r.pxname, mode: r.mode, scur: r.scur, stot: r.stot,
			rate: r.rate, reqRate: r.reqRate, bin: r.bin, bout: r.bout,
			hrsp2xx: r.hrsp2xx, hrsp3xx: r.hrsp3xx, hrsp4xx: r.hrsp4xx, hrsp5xx: r.hrsp5xx,
			ereq: r.ereq, econ: r.econ, eresp: r.eresp,
		})
	}
	sort.Slice(feDetails, func(i, j int) bool { return feDetails[i].reqRate > feDetails[j].reqRate })

	feCount := len(feDetails)
	if feCount > 5 { feCount = 5 }
	inst.DeepMetrics["fe_detail_count"] = fmt.Sprintf("%d", feCount)
	for i := 0; i < feCount; i++ {
		fd := feDetails[i]
		pfx := fmt.Sprintf("fe_detail_%d_", i)
		inst.DeepMetrics[pfx+"name"] = fd.name
		inst.DeepMetrics[pfx+"mode"] = fd.mode
		inst.DeepMetrics[pfx+"scur"] = fmt.Sprintf("%d", fd.scur)
		inst.DeepMetrics[pfx+"stot"] = fmt.Sprintf("%d", fd.stot)
		inst.DeepMetrics[pfx+"rate"] = fmt.Sprintf("%d", fd.rate)
		inst.DeepMetrics[pfx+"req_rate"] = fmt.Sprintf("%d", fd.reqRate)
		inst.DeepMetrics[pfx+"bin"] = fmt.Sprintf("%d", fd.bin)
		inst.DeepMetrics[pfx+"bout"] = fmt.Sprintf("%d", fd.bout)
		inst.DeepMetrics[pfx+"2xx"] = fmt.Sprintf("%d", fd.hrsp2xx)
		inst.DeepMetrics[pfx+"4xx"] = fmt.Sprintf("%d", fd.hrsp4xx)
		inst.DeepMetrics[pfx+"5xx"] = fmt.Sprintf("%d", fd.hrsp5xx)
		inst.DeepMetrics[pfx+"econ"] = fmt.Sprintf("%d", fd.econ)
		// Frontend health
		feHealth := "HEALTHY"
		if fd.stot > 0 {
			errPct := float64(fd.hrsp5xx+fd.econ) / float64(fd.stot) * 100
			if errPct > 5 { feHealth = "CRITICAL" } else if errPct > 1 { feHealth = "DEGRADED" }
		}
		inst.DeepMetrics[pfx+"health"] = feHealth
	}

	// ── Per-backend Mbps calculation ────────────────────────────────────
	// Re-sort backends by traffic for Mbps display (already sorted by sessRate for display above)
	sort.Slice(allBackends, func(i, j int) bool { return allBackends[i].bout > allBackends[j].bout })
	topMbps := len(allBackends)
	if topMbps > 10 { topMbps = 10 }
	for i := 0; i < topMbps; i++ {
		bd := allBackends[i]
		pfx := fmt.Sprintf("be_traffic_%d_", i)
		inst.DeepMetrics[pfx+"name"] = bd.name
		inst.DeepMetrics[pfx+"addr"] = bd.serverAddr
		inst.DeepMetrics[pfx+"bin"] = fmt.Sprintf("%d", bd.bin)
		inst.DeepMetrics[pfx+"bout"] = fmt.Sprintf("%d", bd.bout)
	}
	inst.DeepMetrics["be_traffic_count"] = fmt.Sprintf("%d", topMbps)
}

// collectHAProxySocketStats collects stats via Unix socket. Returns true if successful.
func collectHAProxySocketStats(inst *model.AppInstance, socketPath string, health *haproxyHealth, cfgMaxConn int) bool {
	gotAny := false

	// show info
	infoRaw, err := haproxyShowInfo(socketPath)
	if err == nil && len(infoRaw) > 0 {
		info := parseHAProxyInfo(infoRaw)
		if len(info) > 0 {
			applyHAProxyInfoMetrics(inst, info, health)
			gotAny = true
		}
	}

	// show stat
	statRaw, err := haproxyShowStat(socketPath)
	if err == nil && len(statRaw) > 0 {
		rows := parseHAProxyStats(statRaw)
		if len(rows) > 0 {
			applyHAProxyStatMetrics(inst, rows, health, cfgMaxConn)
			gotAny = true
		}
	}

	// show sess — parse for inbound IP breakdown (lightweight: only count per source IP)
	if sessRaw, err := haproxySockCmd(socketPath, "show sess\n"); err == nil {
		applyHAProxySessMetrics(inst, sessRaw)
	}

	return gotAny
}

// haproxySockCmd sends a command to HAProxy socket and returns the output.
func haproxySockCmd(socketPath, cmd string) (string, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, cmd)
	data, err := io.ReadAll(conn)
	return string(data), err
}

// applyHAProxySessMetrics parses "show sess" output + TCP state from /proc/net/tcp
// to build comprehensive inbound traffic analysis.
func applyHAProxySessMetrics(inst *model.AppInstance, raw string) {
	type ipInfo struct {
		ip       string
		count    int
		frontend string // most common frontend
		feMap    map[string]int
	}
	ipData := make(map[string]*ipInfo)
	totalSess := 0

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		srcIdx := strings.Index(line, "src=")
		if srcIdx < 0 {
			continue
		}
		totalSess++
		// Extract source IP
		rest := line[srcIdx+4:]
		spaceIdx := strings.IndexByte(rest, ' ')
		if spaceIdx > 0 {
			rest = rest[:spaceIdx]
		}
		if colonIdx := strings.LastIndex(rest, ":"); colonIdx > 0 {
			rest = rest[:colonIdx]
		}
		ip := rest

		info, ok := ipData[ip]
		if !ok {
			info = &ipInfo{ip: ip, feMap: make(map[string]int)}
			ipData[ip] = info
		}
		info.count++

		// Extract frontend name
		feIdx := strings.Index(line, "fe=")
		if feIdx >= 0 {
			feRest := line[feIdx+3:]
			if si := strings.IndexByte(feRest, ' '); si > 0 {
				feRest = feRest[:si]
			}
			info.feMap[feRest]++
		}
	}

	if totalSess == 0 {
		return
	}

	// Resolve most-used frontend per IP
	for _, info := range ipData {
		maxCnt := 0
		for fe, cnt := range info.feMap {
			if cnt > maxCnt {
				maxCnt = cnt
				info.frontend = fe
			}
		}
	}

	// Sort by count
	type ipSorted struct {
		ip       string
		count    int
		frontend string
	}
	var ips []ipSorted
	for _, info := range ipData {
		ips = append(ips, ipSorted{info.ip, info.count, info.frontend})
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].count > ips[j].count })

	// TCP state analysis — split by frontend (inbound) vs backend (outbound)
	workerPID, _ := strconv.Atoi(inst.DeepMetrics["worker_pid"])
	if workerPID == 0 {
		workerPID = inst.PID
	}
	listenPortSet := make(map[int]bool)
	if lp := inst.DeepMetrics["listen_ports"]; lp != "" {
		for _, ps := range strings.Split(lp, ",") {
			if p, err := strconv.Atoi(strings.TrimSpace(ps)); err == nil {
				listenPortSet[p] = true
			}
		}
	}
	tcpBreakdown := parseTCPStatesByDirection(workerPID, listenPortSet)

	inst.DeepMetrics["inbound_active_sess"] = fmt.Sprintf("%d", totalSess)
	inst.DeepMetrics["inbound_total_unique"] = fmt.Sprintf("%d", len(ips))

	// Frontend (inbound) TCP states
	feTotal := 0
	for _, v := range tcpBreakdown.frontend { feTotal += v }
	inst.DeepMetrics["fe_tcp_established"] = fmt.Sprintf("%d", tcpBreakdown.frontend["ESTABLISHED"])
	inst.DeepMetrics["fe_tcp_time_wait"] = fmt.Sprintf("%d", tcpBreakdown.frontend["TIME_WAIT"])
	inst.DeepMetrics["fe_tcp_close_wait"] = fmt.Sprintf("%d", tcpBreakdown.frontend["CLOSE_WAIT"])
	inst.DeepMetrics["fe_tcp_fin_wait1"] = fmt.Sprintf("%d", tcpBreakdown.frontend["FIN_WAIT1"])
	inst.DeepMetrics["fe_tcp_fin_wait2"] = fmt.Sprintf("%d", tcpBreakdown.frontend["FIN_WAIT2"])
	inst.DeepMetrics["fe_tcp_syn_recv"] = fmt.Sprintf("%d", tcpBreakdown.frontend["SYN_RECV"])
	inst.DeepMetrics["fe_tcp_last_ack"] = fmt.Sprintf("%d", tcpBreakdown.frontend["LAST_ACK"])
	inst.DeepMetrics["fe_tcp_listen"] = fmt.Sprintf("%d", tcpBreakdown.frontend["LISTEN"])
	inst.DeepMetrics["fe_tcp_total"] = fmt.Sprintf("%d", feTotal)

	// Backend (outbound) TCP states
	beTotal := 0
	for _, v := range tcpBreakdown.backend { beTotal += v }
	inst.DeepMetrics["be_tcp_established"] = fmt.Sprintf("%d", tcpBreakdown.backend["ESTABLISHED"])
	inst.DeepMetrics["be_tcp_time_wait"] = fmt.Sprintf("%d", tcpBreakdown.backend["TIME_WAIT"])
	inst.DeepMetrics["be_tcp_close_wait"] = fmt.Sprintf("%d", tcpBreakdown.backend["CLOSE_WAIT"])
	inst.DeepMetrics["be_tcp_fin_wait1"] = fmt.Sprintf("%d", tcpBreakdown.backend["FIN_WAIT1"])
	inst.DeepMetrics["be_tcp_fin_wait2"] = fmt.Sprintf("%d", tcpBreakdown.backend["FIN_WAIT2"])
	inst.DeepMetrics["be_tcp_syn_sent"] = fmt.Sprintf("%d", tcpBreakdown.backend["SYN_SENT"])
	inst.DeepMetrics["be_tcp_last_ack"] = fmt.Sprintf("%d", tcpBreakdown.backend["LAST_ACK"])
	inst.DeepMetrics["be_tcp_total"] = fmt.Sprintf("%d", beTotal)

	inst.DeepMetrics["tcp_total"] = fmt.Sprintf("%d", feTotal+beTotal)

	// Top IPs per direction with their TCP states
	storeTopIPs := func(prefix string, perIP map[string]map[string]int) {
		// Sort by total connection count
		type ipEntry struct {
			ip    string
			total int
			states map[string]int
		}
		var entries []ipEntry
		for ip, states := range perIP {
			total := 0
			for _, c := range states { total += c }
			entries = append(entries, ipEntry{ip, total, states})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].total > entries[j].total })
		n := len(entries)
		if n > 3 { n = 3 }
		inst.DeepMetrics[prefix+"count"] = fmt.Sprintf("%d", n)
		for i := 0; i < n; i++ {
			pfx := fmt.Sprintf("%s%d_", prefix, i)
			inst.DeepMetrics[pfx+"ip"] = entries[i].ip
			inst.DeepMetrics[pfx+"total"] = fmt.Sprintf("%d", entries[i].total)
			// Build state string: "ESTABLISHED:400 CLOSE_WAIT:5 SYN_SENT:2"
			var parts []string
			// Order states by count descending
			type sc struct{ s string; c int }
			var scs []sc
			for s, c := range entries[i].states {
				scs = append(scs, sc{s, c})
			}
			sort.Slice(scs, func(a, b int) bool { return scs[a].c > scs[b].c })
			for _, x := range scs {
				parts = append(parts, fmt.Sprintf("%s:%d", x.s, x.c))
			}
			inst.DeepMetrics[pfx+"states"] = strings.Join(parts, " ")
		}
	}
	storeTopIPs("fe_top_ip_", tcpBreakdown.fePerIP)
	storeTopIPs("be_top_ip_", tcpBreakdown.bePerIP)

	// Inbound health assessment — structured RCA per issue
	inboundHealth := "HEALTHY"
	type inboundIssue struct {
		title    string
		cause    string
		evidence string
		blame    string
		fix      string
		severity string // WARN or CRIT
	}
	var inboundIssues []inboundIssue

	// Frontend (inbound) TCP issues
	feCW := tcpBreakdown.frontend["CLOSE_WAIT"]
	if feCW > 50 {
		inboundHealth = "DEGRADED"
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%d frontend CLOSE_WAIT (clients → HAProxy)", feCW),
			cause:    "Clients closed their connections but HAProxy hasn't called close() yet. HAProxy is holding dead inbound sockets.",
			evidence: fmt.Sprintf("Frontend: CLOSE_WAIT=%d, ESTABLISHED=%d, total=%d.", feCW, tcpBreakdown.frontend["ESTABLISHED"], feTotal),
			blame:    "Our side — HAProxy not closing inbound client sockets promptly.",
			fix:      "1) Lower 'timeout client' in HAProxy. 2) Check 'option http-server-close'. 3) Check for HAProxy bugs or resource exhaustion.",
			severity: "CRIT",
		})
	}
	beCW := tcpBreakdown.backend["CLOSE_WAIT"]
	if beCW > 20 {
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%d backend CLOSE_WAIT (HAProxy → suppliers)", beCW),
			cause:    "Supplier endpoints closed their connections but HAProxy hasn't released the sockets. Connection leak on outbound side.",
			evidence: fmt.Sprintf("Backend: CLOSE_WAIT=%d, ESTABLISHED=%d, total=%d.", beCW, tcpBreakdown.backend["ESTABLISHED"], beTotal),
			blame:    "Our side — HAProxy holding stale outbound connections after supplier disconnected.",
			fix:      "1) Lower 'timeout server' in HAProxy. 2) Check 'option http-server-close' or 'option forceclose'. 3) Review connection reuse settings.",
			severity: "WARN",
		})
	}

	feTW := tcpBreakdown.frontend["TIME_WAIT"]
	if feTW > 1000 {
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%d frontend TIME_WAIT (inbound churn)", feTW),
			cause:    "High inbound connection churn — many short-lived client connections being created and torn down rapidly.",
			evidence: fmt.Sprintf("Frontend TIME_WAIT=%d (threshold: 1000).", feTW),
			blame:    "Traffic pattern — clients not using keep-alive. Not a fault but wastes resources.",
			fix:      "1) Enable 'option http-keep-alive' in HAProxy. 2) Tune 'net.ipv4.tcp_tw_reuse=1'.",
			severity: "WARN",
		})
	}

	feFW := tcpBreakdown.frontend["FIN_WAIT1"] + tcpBreakdown.frontend["FIN_WAIT2"]
	if feFW > 50 {
		inboundHealth = "DEGRADED"
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%d frontend FIN_WAIT (inbound teardown stuck)", feFW),
			cause:    "HAProxy sent FIN to clients but they're not completing the close. Clients may be unresponsive or network dropping FIN packets.",
			evidence: fmt.Sprintf("Frontend: FIN_WAIT1=%d, FIN_WAIT2=%d.", tcpBreakdown.frontend["FIN_WAIT1"], tcpBreakdown.frontend["FIN_WAIT2"]),
			blame:    "Client side — clients not completing TCP close handshake.",
			fix:      "1) Lower 'net.ipv4.tcp_fin_timeout'. 2) Check client network quality.",
			severity: "WARN",
		})
	}

	beSS := tcpBreakdown.backend["SYN_SENT"]
	if beSS > 20 {
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%d backend SYN_SENT (outbound connect pending)", beSS),
			cause:    "HAProxy is trying to connect to supplier endpoints but SYN hasn't been ACK'd yet. Suppliers are slow to accept or unreachable.",
			evidence: fmt.Sprintf("Backend SYN_SENT=%d. These are outbound connections waiting for supplier TCP handshake.", beSS),
			blame:    "Supplier side — endpoints slow to accept connections or network latency.",
			fix:      "1) Check supplier endpoint health. 2) Increase 'timeout connect' if needed. 3) Check DNS resolution speed.",
			severity: "WARN",
		})
	}

	feSR := tcpBreakdown.frontend["SYN_RECV"]
	if feSR > 20 {
		inboundHealth = "DEGRADED"
		sev := "WARN"
		if feSR > 100 { inboundHealth = "CRITICAL"; sev = "CRIT" }
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%d frontend SYN_RECV (incomplete inbound handshakes)", feSR),
			cause:    "Clients sent SYN but haven't completed the 3-way handshake. Possible SYN flood or very slow clients.",
			evidence: fmt.Sprintf("Frontend SYN_RECV=%d (threshold: 20). Normal is 0-5.", feSR),
			blame:    "External — SYN flood attack or poor client network quality.",
			fix:      "1) Enable SYN cookies: 'net.ipv4.tcp_syncookies=1'. 2) Rate limit with iptables. 3) Check 'net.ipv4.tcp_max_syn_backlog'.",
			severity: sev,
		})
	}

	// Check frontend client aborts from already-collected metrics
	cliAborts, _ := strconv.ParseInt(inst.DeepMetrics["client_aborts"], 10, 64)
	totalReqs, _ := strconv.ParseInt(inst.DeepMetrics["total_requests"], 10, 64)
	if cliAborts > 0 && totalReqs > 0 {
		abortPct := float64(cliAborts) / float64(totalReqs) * 100
		inst.DeepMetrics["inbound_abort_pct"] = fmt.Sprintf("%.2f", abortPct)
		if abortPct > 1 {
			inboundHealth = "DEGRADED"
			// Determine likely cause based on other metrics
			avgRtime, _ := strconv.ParseFloat(inst.DeepMetrics["avg_response_time_ms"], 64)
			be5xx, _ := strconv.ParseInt(inst.DeepMetrics["be_5xx"], 10, 64)
			blameTxt := "Likely our side — backends too slow, causing clients to give up waiting."
			if avgRtime > 5000 {
				blameTxt = "Our side — avg response time " + fmt.Sprintf("%.0fms", avgRtime) + " is extremely slow. Clients disconnect before receiving response."
			} else if be5xx > 1000 {
				blameTxt = "Our side — high 5xx error rate from backends. Clients may be retrying and aborting."
			}
			inboundIssues = append(inboundIssues, inboundIssue{
				title:    fmt.Sprintf("%.2f%% client abort rate (%s aborts of %s total)", abortPct, formatCount(cliAborts), formatCount(totalReqs)),
				cause:    "Clients are disconnecting before receiving a complete response. This means HAProxy or backends are taking too long to respond, and clients give up (timeout or user navigated away).",
				evidence: fmt.Sprintf("Client aborts: %s, Total requests: %s, Abort rate: %.2f%% (threshold: 1%%). Avg backend response: %sms.", formatCount(cliAborts), formatCount(totalReqs), abortPct, inst.DeepMetrics["avg_response_time_ms"]),
				blame:    blameTxt,
				fix:      "1) Optimize slow backends (check BACKEND HEALTH table for slow endpoints). 2) Increase client timeout if clients are legitimate (timeout client). 3) Add caching for slow responses. 4) Check backend connection limits (maxconn per server).",
				severity: "WARN",
			})
		}
	}

	// Connection errors — deep analysis per backend
	beReqTot2, _ := strconv.ParseInt(inst.DeepMetrics["be_req_total"], 10, 64)
	feReqTot2, _ := strconv.ParseInt(inst.DeepMetrics["fe_req_total"], 10, 64)
	currConnI, _ := strconv.ParseInt(inst.DeepMetrics["curr_conn"], 10, 64)
	maxConnI, _ := strconv.ParseInt(inst.DeepMetrics["max_conn"], 10, 64)

	// Analyze per-backend connection errors from raw stat rows
	type beEconEntry struct {
		name       string
		econ       int64
		wretr      int64
		stot       int64
		srvAddr    string
		srvStatus  string
		errPct     float64
		isDefault  bool   // is this the default_backend?
		isLocalhost bool  // does it point to localhost/127.0.0.1?
	}
	var beEconList []beEconEntry

	// Re-parse stats to get per-backend econ with server details
	sockPath := inst.DeepMetrics["stats_socket"]
	if sockPath != "" {
		rawStat, _ := haproxyShowStat(sockPath)
		if rawStat != "" {
			statRows := parseHAProxyStats(rawStat)
			// Build map: backend_name -> {server_addr, server_econ, server_status}
			type srvInfo struct{ addr, status string; econ, wretr int64 }
			srvMap := make(map[string]srvInfo)
			for _, r := range statRows {
				if r.svname != "FRONTEND" && r.svname != "BACKEND" {
					if r.econ > 0 || r.addr != "" {
						si := srvMap[r.pxname]
						si.addr = r.addr
						si.status = r.status
						si.econ += r.econ
						si.wretr += r.wretr
						srvMap[r.pxname] = si
					}
				}
			}
			// Check default_backend from config
			defaultBE := inst.DeepMetrics["default_backend"]
			for _, r := range statRows {
				if r.svname == "BACKEND" && r.econ > 0 {
					si := srvMap[r.pxname]
					entry := beEconEntry{
						name:      r.pxname,
						econ:      r.econ,
						wretr:     r.wretr,
						stot:      r.stot,
						srvAddr:   si.addr,
						srvStatus: si.status,
						isDefault: r.pxname == defaultBE,
					}
					if r.stot > 0 { entry.errPct = float64(r.econ) / float64(r.stot) * 100 }
					entry.isLocalhost = strings.HasPrefix(entry.srvAddr, "127.0.0.1:") || strings.HasPrefix(entry.srvAddr, "localhost:")
					beEconList = append(beEconList, entry)
				}
			}
		}
	}

	// Sort by econ descending
	sort.Slice(beEconList, func(i, j int) bool { return beEconList[i].econ > beEconList[j].econ })

	totalEcon, _ := strconv.ParseInt(inst.DeepMetrics["connection_errors"], 10, 64)
	if totalEcon > 100 && len(beEconList) > 0 {
		top := beEconList[0]

		// Determine if dominant source is a fallback/default backend pointing to nothing
		if top.isDefault && top.isLocalhost && top.econ > 0 {
			// Default backend pointing to localhost — connection refused = nothing listening
			retryRatio := float64(0)
			if top.econ > 0 { retryRatio = float64(top.wretr) / float64(top.econ) }
			errOfTotal := float64(0)
			if beReqTot2 > 0 { errOfTotal = float64(top.econ) / float64(beReqTot2) * 100 }

			sev := "WARN"
			if top.errPct > 50 { sev = "CRIT" }

			inboundIssues = append(inboundIssues, inboundIssue{
				title: fmt.Sprintf("%s conn errors on default_backend '%s' → %s (%.1f%% failure rate)",
					formatCount(top.econ), top.name, top.srvAddr, top.errPct),
				cause: fmt.Sprintf("Requests not matching any ACL rule fall through to default_backend '%s', which forwards to %s. Nothing is listening on that address — every connection is refused. HAProxy retries %dx per request, amplifying the error count (retries: %s).",
					top.name, top.srvAddr, int(retryRatio), formatCount(top.wretr)),
				evidence: fmt.Sprintf("Backend '%s': econ=%s, retries=%s, total_sessions=%s, failure_rate=%.1f%%. Server addr: %s, status: '%s'. This backend accounts for %.3f%% of total outbound traffic — it's the catch-all for unmatched requests.",
					top.name, formatCount(top.econ), formatCount(top.wretr), formatCount(top.stot), top.errPct, top.srvAddr, top.srvStatus, errOfTotal),
				blame: fmt.Sprintf("Configuration issue — '%s' is the default_backend but points to %s where no service is running. These are not real traffic errors — they are unmatched requests hitting a dead-end.", top.name, top.srvAddr),
				fix: fmt.Sprintf("1) Start a service on %s to handle fallback requests, OR 2) Change default_backend to return HTTP 403/503 directly using 'http-request deny' instead of proxying to a dead endpoint, OR 3) If these requests are unwanted, add 'http-request silent-drop' to reject them without error logging, OR 4) Remove default_backend and let unmatched requests get rejected at the frontend level.", top.srvAddr),
				severity: sev,
			})
		} else if top.econ > 0 {
			// Real backend with connection errors — supplier issue
			errOfTotal := float64(0)
			if beReqTot2 > 0 { errOfTotal = float64(top.econ) / float64(beReqTot2) * 100 }

			// Build detailed per-backend breakdown
			breakdown := []string{}
			for i := 0; i < len(beEconList) && i < 5; i++ {
				be := beEconList[i]
				breakdown = append(breakdown, fmt.Sprintf("%s: econ=%s retries=%s addr=%s status=%s (%.1f%% fail)",
					be.name, formatCount(be.econ), formatCount(be.wretr), be.srvAddr, be.srvStatus, be.errPct))
			}

			sev := "WARN"
			if top.errPct > 10 { sev = "CRIT" }

			causeTxt := fmt.Sprintf("HAProxy cannot establish TCP connections to '%s' at %s. The endpoint is either down, firewalled, overloaded, or DNS is stale.", top.name, top.srvAddr)
			blameTxt := fmt.Sprintf("Supplier side — endpoint %s (%s) is not accepting connections. Server status: '%s'.", top.srvAddr, top.name, top.srvStatus)
			if top.srvStatus == "DOWN" {
				causeTxt = fmt.Sprintf("Server at %s (%s) is marked DOWN by HAProxy health checks. All traffic to this backend fails.", top.srvAddr, top.name)
			}

			inboundIssues = append(inboundIssues, inboundIssue{
				title:    fmt.Sprintf("%s outbound conn errors — top: '%s' → %s", formatCount(totalEcon), top.name, top.srvAddr),
				cause:    causeTxt,
				evidence: fmt.Sprintf("Per-backend breakdown:\n%s\nTotal outbound econ: %s (%.3f%% of %s backend requests).", strings.Join(breakdown, "\n"), formatCount(totalEcon), errOfTotal, formatCount(beReqTot2)),
				blame:    blameTxt,
				fix:      fmt.Sprintf("1) Verify endpoint %s is reachable: 'curl -v %s'. 2) Check DNS resolution for the backend hostname. 3) Check firewall rules. 4) If server is intentionally down, remove from backend or set to 'maint'.", top.srvAddr, top.srvAddr),
				severity: sev,
			})
		}

		// Report other backends with significant errors (after the main one)
		for i := 1; i < len(beEconList) && i < 4; i++ {
			be := beEconList[i]
			if be.econ < 10 { continue }
			inboundIssues = append(inboundIssues, inboundIssue{
				title:    fmt.Sprintf("%s conn errors on '%s' → %s (%.1f%% failure rate)", formatCount(be.econ), be.name, be.srvAddr, be.errPct),
				cause:    fmt.Sprintf("Backend '%s' failing to connect to %s. Retries: %s.", be.name, be.srvAddr, formatCount(be.wretr)),
				evidence: fmt.Sprintf("econ=%s, retries=%s, sessions=%s, addr=%s, status=%s.", formatCount(be.econ), formatCount(be.wretr), formatCount(be.stot), be.srvAddr, be.srvStatus),
				blame:    fmt.Sprintf("Endpoint %s — intermittent failures (%.1f%% of sessions fail).", be.srvAddr, be.errPct),
				fix:      fmt.Sprintf("Check health of %s. If transient, increase retries/timeout connect.", be.srvAddr),
				severity: "WARN",
			})
		}
	}

	// Frontend request errors (ereq) — separate from connection errors
	feEreq, _ := strconv.ParseInt(inst.DeepMetrics["fe_ereq"], 10, 64)
	if feEreq > 100 && feReqTot2 > 0 {
		ereqPct := float64(feEreq) / float64(feReqTot2) * 100
		sev := "WARN"
		if ereqPct > 5 { sev = "CRIT" }
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%s request errors on frontends (%.2f%% of traffic)", formatCount(feEreq), ereqPct),
			cause:    "HTTP protocol errors: malformed requests, invalid HTTP method/version, header too large, or client disconnected during request send.",
			evidence: fmt.Sprintf("Frontend ereq: %s out of %s requests (%.2f%%). These are client-side protocol violations, not server errors.", formatCount(feEreq), formatCount(feReqTot2), ereqPct),
			blame:    "Client side — malformed HTTP requests from clients. Could be bots, scanners, or misconfigured client applications.",
			fix:      "1) Check HAProxy logs for the actual malformed requests. 2) If from bots/scanners, consider IP blocking. 3) If ereq is stable and low %, this is normal noise.",
			severity: sev,
		})
	}

	// Maxconn capacity check
	if maxConnI > 0 && currConnI > 0 {
		connPct := float64(currConnI) / float64(maxConnI) * 100
		if connPct > 80 {
			sev := "WARN"
			if connPct > 95 { sev = "CRIT"; inboundHealth = "CRITICAL" } else { inboundHealth = "DEGRADED" }
			inboundIssues = append(inboundIssues, inboundIssue{
				title:    fmt.Sprintf("Connection capacity at %.0f%% (%s/%s)", connPct, formatCount(currConnI), formatCount(maxConnI)),
				cause:    "HAProxy is approaching its maxconn limit. New connections will be rejected when full.",
				evidence: fmt.Sprintf("Current: %s, Max: %s, Usage: %.1f%%.", formatCount(currConnI), formatCount(maxConnI), connPct),
				blame:    "Our side — need to increase capacity.",
				fix:      "1) Increase global maxconn in haproxy.cfg. 2) Check ulimit -n. 3) Tune net.core.somaxconn.",
				severity: sev,
			})
		}
	}

	// Queue check
	qCur, _ := strconv.ParseInt(inst.DeepMetrics["queue_current"], 10, 64)
	if qCur > 0 {
		inboundHealth = "DEGRADED"
		inboundIssues = append(inboundIssues, inboundIssue{
			title:    fmt.Sprintf("%d requests currently queued", qCur),
			cause:    "All backend servers have reached their maxconn limit. New requests are waiting in the HAProxy queue for a backend slot to become available.",
			evidence: fmt.Sprintf("Queue depth: %d. This means %d clients are actively waiting for a response.", qCur, qCur),
			blame:    "Our side — backend capacity is insufficient for the current request rate.",
			fix:      "1) Increase 'maxconn' on backend servers. 2) Add more backend servers. 3) Optimize backend response time to free slots faster. 4) Set 'timeout queue' to fail fast rather than wait indefinitely.",
			severity: "CRIT",
		})
	}

	inst.DeepMetrics["inbound_health"] = inboundHealth
	inst.DeepMetrics["inbound_issue_count"] = fmt.Sprintf("%d", len(inboundIssues))
	for i, iss := range inboundIssues {
		pre := fmt.Sprintf("inbound_issue_%d_", i)
		inst.DeepMetrics[pre+"title"] = iss.title
		inst.DeepMetrics[pre+"cause"] = iss.cause
		inst.DeepMetrics[pre+"evidence"] = iss.evidence
		inst.DeepMetrics[pre+"blame"] = iss.blame
		inst.DeepMetrics[pre+"fix"] = iss.fix
		inst.DeepMetrics[pre+"severity"] = iss.severity
	}

	// Store per-IP data
	topN := len(ips)
	if topN > 10 { topN = 10 }
	inst.DeepMetrics["inbound_ip_count"] = fmt.Sprintf("%d", topN)
	for i := 0; i < topN; i++ {
		pfx := fmt.Sprintf("inbound_ip_%d_", i)
		inst.DeepMetrics[pfx+"addr"] = ips[i].ip
		inst.DeepMetrics[pfx+"conns"] = fmt.Sprintf("%d", ips[i].count)
		inst.DeepMetrics[pfx+"frontend"] = ips[i].frontend
		if totalSess > 0 {
			inst.DeepMetrics[pfx+"pct"] = fmt.Sprintf("%.1f", float64(ips[i].count)/float64(totalSess)*100)
		}
	}
}

// tcpIPState tracks per-IP TCP state counts.
type tcpIPState struct {
	ip     string
	states map[string]int
	total  int
}

// tcpStateBreakdown holds frontend (inbound) and backend (outbound) TCP states separately.
type tcpStateBreakdown struct {
	frontend   map[string]int // connections where local port = listening port (clients → HAProxy)
	backend    map[string]int // connections where local port ≠ listening port (HAProxy → suppliers)
	fePerIP    map[string]map[string]int // frontend: remote_ip → {state → count}
	bePerIP    map[string]map[string]int // backend: remote_ip → {state → count}
}

// parseTCPStatesByDirection splits TCP states into frontend (inbound) vs backend (outbound)
// based on whether the local port is a HAProxy listening port.
// Uses PID socket inodes to only count connections owned by HAProxy.
func parseTCPStatesByDirection(pid int, listenPorts map[int]bool) tcpStateBreakdown {
	result := tcpStateBreakdown{
		frontend: make(map[string]int),
		backend:  make(map[string]int),
		fePerIP:  make(map[string]map[string]int),
		bePerIP:  make(map[string]map[string]int),
	}
	if pid <= 0 {
		return result
	}

	stateMap := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}

	// Build hex port set for matching
	hexPorts := make(map[string]bool, len(listenPorts))
	for p := range listenPorts {
		hexPorts[fmt.Sprintf("%04X", p)] = true
	}

	// Collect socket inodes from /proc/PID/fd/
	socketInodes := make(map[string]bool)
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return result
	}
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			socketInodes[link[8:len(link)-1]] = true
		}
	}
	if len(socketInodes) == 0 {
		return result
	}

	// Scan /proc/net/tcp{,6} and classify each connection
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // skip header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			// Only count sockets owned by this PID
			if !socketInodes[fields[9]] {
				continue
			}
			stateName, ok := stateMap[fields[3]]
			if !ok {
				continue
			}
			// fields[1] = local_address, fields[2] = remote_address (IP:PORT in hex)
			localParts := strings.Split(fields[1], ":")
			if len(localParts) < 2 {
				continue
			}
			localPort := localParts[len(localParts)-1]

			// Extract remote IP (decode hex IP)
			remoteParts := strings.Split(fields[2], ":")
			remoteIP := ""
			if len(remoteParts) >= 2 {
				remoteIP = hexToIP(remoteParts[0])
			}

			if hexPorts[localPort] {
				result.frontend[stateName]++
				if remoteIP != "" {
					if result.fePerIP[remoteIP] == nil {
						result.fePerIP[remoteIP] = make(map[string]int)
					}
					result.fePerIP[remoteIP][stateName]++
				}
			} else {
				result.backend[stateName]++
				if remoteIP != "" {
					if result.bePerIP[remoteIP] == nil {
						result.bePerIP[remoteIP] = make(map[string]int)
					}
					result.bePerIP[remoteIP][stateName]++
				}
			}
		}
		f.Close()
	}
	return result
}

// hexToIP converts a hex-encoded IP from /proc/net/tcp to dotted decimal.
// IPv4: 8 hex chars (little-endian 32-bit), IPv6: 32 hex chars.
func hexToIP(hex string) string {
	if len(hex) == 8 {
		// IPv4: stored as little-endian 32-bit
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
			b[i] = byte(v)
		}
		// /proc/net/tcp stores IPv4 in host byte order (little-endian on x86)
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	// IPv6 or unknown — return as-is (truncated)
	if len(hex) == 32 {
		return "ipv6"
	}
	return hex
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

// collectHAProxyHTTPStats tries to fetch stats via HTTP stats CSV endpoint.
func collectHAProxyHTTPStats(inst *model.AppInstance, port int, health *haproxyHealth, cfgMaxConn int) bool {
	// Try common stats URIs
	uris := []string{"/stats;csv", "/haproxy?stats;csv", "/admin?stats;csv"}

	client := &http.Client{Timeout: 3 * time.Second}

	for _, uri := range uris {
		url := fmt.Sprintf("http://127.0.0.1:%d%s", port, uri)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		raw := string(body)
		if !strings.Contains(raw, "pxname") {
			continue
		}

		rows := parseHAProxyStats(raw)
		if len(rows) > 0 {
			applyHAProxyStatMetrics(inst, rows, health, cfgMaxConn)
			inst.DeepMetrics["stats_source"] = "http"
			return true
		}
	}

	return false
}

// formatCount formats a large integer with K/M suffixes for readability.
func formatCount(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.0fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.0fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

// isPrivateAddr checks if an addr (ip:port) is a private/internal IP.
func isPrivateAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// RFC 1918 + loopback + link-local
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"}
	for _, cidr := range private {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
