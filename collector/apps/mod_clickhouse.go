//go:build linux

package apps

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ClickHouse — column-store OLAP database. Process is named
// "clickhouse-serv" (truncated to 15 chars in /proc/<pid>/comm), with
// the watchdog appearing as "clickhouse-watc". The native client
// protocol listens on port 9000 by default; the MySQL-compatibility
// port is 9004, PostgreSQL-compat is 9005, HTTP is 8123, secure HTTP
// 8443.
//
// Tier 1 metrics come from /proc.
// Tier 2 metrics come from clickhouse-client running queries against
// system.* tables — credentials configurable via secrets.ClickHouse,
// otherwise we try the unauthenticated default user (which works on
// many out-of-the-box installs).
type clickhouseModule struct{}

func NewClickHouseModule() AppModule { return &clickhouseModule{} }

func (m *clickhouseModule) Type() string        { return "clickhouse" }
func (m *clickhouseModule) DisplayName() string { return "ClickHouse" }

func (m *clickhouseModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	// Candidates: every process whose truncated comm is "clickhouse-serv".
	// We pick ONE per listening port — typically the watchdog spawns the
	// real server which spawns helper processes that all share argv[0].
	// Picking by lowest PID gives us the parent (most-stable, longest-lived).
	type cand struct {
		pid     int
		port    int
		cmdline string
		comm    string
	}
	byPort := map[int]cand{}
	for _, p := range processes {
		if p.Comm != "clickhouse-serv" {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "config.xml") &&
			!strings.Contains(cmdline, "--config") {
			continue
		}
		if strings.Contains(cmdline, "watchdog") {
			continue
		}
		port := 9000
		for _, f := range strings.Fields(cmdline) {
			if strings.HasPrefix(f, "--tcp_port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(f, "--tcp_port=")); err == nil {
					port = v
				}
			}
		}
		existing, ok := byPort[port]
		if !ok || p.PID < existing.pid {
			byPort[port] = cand{pid: p.PID, port: port, cmdline: cmdline, comm: p.Comm}
		}
	}
	var detected []DetectedApp
	for _, c := range byPort {
		detected = append(detected, DetectedApp{
			PID:     c.pid,
			Port:    c.port,
			Comm:    c.comm,
			Cmdline: c.cmdline,
			Index:   len(detected),
		})
	}
	return detected
}

func (m *clickhouseModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "clickhouse",
		DisplayName: "ClickHouse",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: /proc-derived process metrics.
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Config + version: try /etc/clickhouse-server/config.xml first.
	confPath := findConfigFile([]string{
		"/etc/clickhouse-server/config.xml",
		"/etc/clickhouse/config.xml",
	})
	inst.ConfigPath = confPath

	// Tier 2: deep metrics via clickhouse-client. Falls back gracefully
	// if the binary isn't on PATH or auth fails — we set NeedsCreds
	// so the UI shows the operator how to add credentials.
	collectClickhouseDeepMetrics(&inst, secrets)
	return inst
}

// chQuery runs `clickhouse-client --query` with a short timeout. Uses
// configured credentials when present; otherwise tries the default
// (unauthenticated) user against 127.0.0.1.
func chQuery(secrets *AppSecrets, query string) (string, error) {
	bin, err := exec.LookPath("clickhouse-client")
	if err != nil {
		// Some installs ship `clickhouse` with a `client` subcommand.
		if bin2, err2 := exec.LookPath("clickhouse"); err2 == nil {
			bin = bin2
		} else {
			return "", err
		}
	}
	args := []string{}
	host := "127.0.0.1"
	port := 9000
	user := ""
	pass := ""
	db := ""
	if secrets != nil && secrets.ClickHouse != nil {
		ch := secrets.ClickHouse
		if ch.Host != "" {
			host = ch.Host
		}
		if ch.Port > 0 {
			port = ch.Port
		}
		user = ch.User
		pass = ch.Password
		db = ch.DBName
	}
	args = append(args, "--host", host, "--port", strconv.Itoa(port))
	if user != "" {
		args = append(args, "--user", user)
	}
	if pass != "" {
		args = append(args, "--password", pass)
	}
	if db != "" {
		args = append(args, "--database", db)
	}
	args = append(args, "--query", query, "--format", "TabSeparated")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	if strings.HasSuffix(bin, "/clickhouse") {
		// `clickhouse client --host ...` rather than `clickhouse-client ...`
		cmd = exec.CommandContext(ctx, bin, append([]string{"client"}, args...)...)
	}
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// collectClickhouseDeepMetrics fills inst.DeepMetrics with the
// signals operators care about: version, query counts, memory,
// replication, slow queries, merges.
func collectClickhouseDeepMetrics(inst *model.AppInstance, secrets *AppSecrets) {
	dm := inst.DeepMetrics
	any := false

	// 1. Version.
	if out, err := chQuery(secrets, "SELECT version()"); err == nil && out != "" {
		any = true
		inst.Version = strings.TrimSpace(out)
		dm["version"] = inst.Version
	}

	// 2. Currently-running queries + active mutations.
	if out, err := chQuery(secrets, "SELECT count() FROM system.processes"); err == nil && out != "" {
		any = true
		dm["active_queries"] = strings.TrimSpace(out)
	}
	if out, err := chQuery(secrets, "SELECT count() FROM system.mutations WHERE NOT is_done"); err == nil && out != "" {
		any = true
		dm["pending_mutations"] = strings.TrimSpace(out)
	}

	// 3. Background merges in flight — high counts mean ingest is
	// outpacing compaction, eventually causing query slowdown.
	if out, err := chQuery(secrets, "SELECT count() FROM system.merges"); err == nil && out != "" {
		any = true
		dm["active_merges"] = strings.TrimSpace(out)
	}

	// 4. Replication queue depth (per-table). If non-zero across many
	// tables, the replica is falling behind.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.replication_queue"); err == nil && out != "" {
		any = true
		dm["replication_queue"] = strings.TrimSpace(out)
	}
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.replicas WHERE is_readonly OR future_parts > 100"); err == nil && out != "" {
		any = true
		dm["replicas_degraded"] = strings.TrimSpace(out)
	}

	// 5. Server-side memory tracker (much more accurate than RSS for
	// CH — it counts query caches, mark cache, primary-key cache).
	if out, err := chQuery(secrets,
		"SELECT value FROM system.asynchronous_metrics WHERE metric='MemoryResident'"); err == nil && out != "" {
		any = true
		if v, err := strconv.ParseFloat(strings.TrimSpace(out), 64); err == nil {
			dm["memory_resident_mb"] = fmt.Sprintf("%.0f", v/1024.0/1024.0)
		}
	}

	// 6. Query throughput (system.events delta over server uptime).
	// We just report the total; rate can be derived by the engine.
	if out, err := chQuery(secrets,
		"SELECT value FROM system.events WHERE event='Query'"); err == nil && out != "" {
		any = true
		dm["queries_total"] = strings.TrimSpace(out)
	}
	if out, err := chQuery(secrets,
		"SELECT value FROM system.events WHERE event='FailedQuery'"); err == nil && out != "" {
		any = true
		dm["queries_failed"] = strings.TrimSpace(out)
	}

	// 7. Slow query indicator — queries currently running > 30s.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.processes WHERE elapsed > 30"); err == nil && out != "" {
		any = true
		dm["long_running_queries"] = strings.TrimSpace(out)
	}

	// 8. Database / part counts (top databases by size).
	if out, err := chQuery(secrets,
		"SELECT database, formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE active GROUP BY database ORDER BY sum(bytes_on_disk) DESC LIMIT 3"); err == nil && out != "" {
		any = true
		var sizes []string
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 {
				sizes = append(sizes, parts[0]+"="+parts[1])
			}
		}
		if len(sizes) > 0 {
			dm["database_sizes"] = strings.Join(sizes, ", ")
		}
	}

	// 9. Detached parts — typically a sign of past corruption.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.detached_parts"); err == nil && out != "" {
		any = true
		dm["detached_parts"] = strings.TrimSpace(out)
	}

	// 10. ZooKeeper sessions (replicated installs only).
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.zookeeper_connection"); err == nil && out != "" {
		any = true
		dm["zookeeper_connections"] = strings.TrimSpace(out)
	}

	if any {
		inst.HasDeepMetrics = true
		inst.NeedsCreds = false
	} else {
		inst.NeedsCreds = true
	}

	// Health scoring — start at 100, dock per issue, similar pattern
	// to mod_postgresql so the UI's HealthScore column is comparable.
	inst.HealthScore = 100
	if !inst.HasDeepMetrics {
		return
	}

	if v, ok := dm["long_running_queries"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Long-running queries (>30s): %d", n))
		}
	}
	if v, ok := dm["active_merges"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 50 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Excessive background merges: %d (ingest outpacing compaction)", n))
		} else if n > 20 {
			inst.HealthScore -= 5
		}
	}
	if v, ok := dm["replication_queue"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 100 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Replication queue backlog: %d entries", n))
		}
	}
	if v, ok := dm["replicas_degraded"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Replicas in degraded state: %d", n))
		}
	}
	if v, ok := dm["detached_parts"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Detached parts present: %d", n))
		}
	}
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
}
