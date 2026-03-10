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
	if app.Port > 0 {
		inst.Connections = countTCPConnections(app.Port)
	}

	inst.ConfigPath = findConfigFile([]string{
		"/etc/haproxy/haproxy.cfg",
		"/usr/local/etc/haproxy/haproxy.cfg",
	})

	// Count worker processes and sum worker RSS
	workerCount := countChildProcesses(app.PID, "haproxy")
	inst.DeepMetrics["workers"] = fmt.Sprintf("%d", workerCount)

	workerRSS := 0.0
	entries, _ := procEntries()
	for _, pid := range entries {
		if pid == app.PID {
			continue
		}
		ppid, pcomm := readPPIDComm(pid)
		if ppid == app.PID && pcomm == "haproxy" {
			workerRSS += readProcRSS(pid)
		}
	}
	inst.RSSMB += workerRSS

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
		if cfg.statsEnabled {
			inst.DeepMetrics["cfg_stats"] = "enabled"
			if cfg.statsURI != "" {
				inst.DeepMetrics["cfg_stats_uri"] = cfg.statsURI
			}
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
	maxConn       int
	nbThread      int
	nbProc        int
	frontendCount int
	backendCount  int
	statsEnabled  bool
	statsURI      string
	statsSockets  []string
}

// parseHAProxyConfig extracts key settings from haproxy.cfg.
func parseHAProxyConfig(path string) haproxyConfig {
	var cfg haproxyConfig

	f, err := os.Open(path)
	if err != nil {
		return cfg
	}
	defer f.Close()

	inGlobal := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Track sections
		if strings.HasPrefix(line, "global") {
			inGlobal = true
			continue
		}
		if len(line) > 0 && line[0] != '#' && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// New section — no longer in global
			if !strings.HasPrefix(line, "global") {
				inGlobal = false
			}
		}

		// Count frontend/backend sections
		if strings.HasPrefix(line, "frontend ") {
			cfg.frontendCount++
		}
		if strings.HasPrefix(line, "backend ") {
			cfg.backendCount++
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
		}
		rows = append(rows, row)
	}
	return rows
}

// backendSession tracks backend names by total sessions for top-N ranking.
type backendSession struct {
	name     string
	sessions int64
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
		respErrors     int64
		retries        int64
		http5xx        int64
		http4xx        int64
		clientAborts   int64
		serverAborts   int64
		queueCurrent   int64
		queueMax       int64
		totalReqs      int64
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
			totalReqs += r.reqTot
			connErrors += r.econ
			respErrors += r.eresp
		case "BACKEND":
			backendCount++
			connErrors += r.econ
			respErrors += r.eresp
			retries += r.wretr
			http5xx += r.hrsp5xx
			http4xx += r.hrsp4xx
			clientAborts += r.cliAbrt
			serverAborts += r.srvAbrt
			queueCurrent += r.qcur
			if r.qmax > queueMax {
				queueMax = r.qmax
			}
			backendSess = append(backendSess, backendSession{
				name:     r.pxname,
				sessions: r.stot,
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
	inst.DeepMetrics["response_errors"] = fmt.Sprintf("%d", respErrors)
	inst.DeepMetrics["retries"] = fmt.Sprintf("%d", retries)
	inst.DeepMetrics["http_5xx"] = fmt.Sprintf("%d", http5xx)
	inst.DeepMetrics["http_4xx"] = fmt.Sprintf("%d", http4xx)
	inst.DeepMetrics["client_aborts"] = fmt.Sprintf("%d", clientAborts)
	inst.DeepMetrics["server_aborts"] = fmt.Sprintf("%d", serverAborts)
	inst.DeepMetrics["queue_current"] = fmt.Sprintf("%d", queueCurrent)
	inst.DeepMetrics["queue_max"] = fmt.Sprintf("%d", queueMax)

	// Top 3 backends by sessions
	if len(backendSess) > 0 {
		sort.Slice(backendSess, func(i, j int) bool {
			return backendSess[i].sessions > backendSess[j].sessions
		})
		var top []string
		for i := 0; i < len(backendSess) && i < 3; i++ {
			top = append(top, fmt.Sprintf("%s(%d)", backendSess[i].name, backendSess[i].sessions))
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

	// Determine proxy role
	proxyRole := "reverse proxy"
	if tcpFrontends > 0 && httpFrontends == 0 {
		proxyRole = "TCP proxy"
	} else if tcpFrontends > 0 && httpFrontends > 0 {
		proxyRole = "HTTP + TCP proxy"
	} else {
		proxyRole = "HTTP reverse proxy"
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

	return gotAny
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
