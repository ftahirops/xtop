//go:build linux

package apps

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type mongoModule struct{}

func NewMongoModule() AppModule { return &mongoModule{} }

func (m *mongoModule) Type() string        { return "mongodb" }
func (m *mongoModule) DisplayName() string { return "MongoDB" }

func (m *mongoModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "mongod" && p.Comm != "mongos" {
			continue
		}
		port := 27017
		cmdline := readProcCmdline(p.PID)
		// Parse --port N from cmdline
		fields := strings.Fields(cmdline)
		for i, f := range fields {
			if f == "--port" && i+1 < len(fields) {
				if v, err := strconv.Atoi(fields[i+1]); err == nil && v > 0 {
					port = v
				}
			}
			if strings.HasPrefix(f, "--port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(f, "--port=")); err == nil && v > 0 {
					port = v
				}
			}
		}

		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    port,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(apps),
		})
	}
	return apps
}

func (m *mongoModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "mongodb",
		DisplayName: "MongoDB",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Config file detection + parsing
	inst.ConfigPath = findConfigFile([]string{
		"/etc/mongod.conf",
		"/etc/mongodb.conf",
		"/usr/local/etc/mongod.conf",
	})

	var configCacheSizeGB float64
	var configMaxConns int
	var configReplSetName string
	if inst.ConfigPath != "" {
		configCacheSizeGB, configMaxConns, configReplSetName = parseMongoConfig(inst.ConfigPath)
		if configCacheSizeGB > 0 {
			inst.DeepMetrics["wt_cache_size_gb"] = fmt.Sprintf("%.1f", configCacheSizeGB)
		}
		if configMaxConns > 0 {
			inst.DeepMetrics["max_connections"] = fmt.Sprintf("%d", configMaxConns)
		}
		if configReplSetName != "" {
			inst.DeepMetrics["config_repl_set"] = configReplSetName
		}
	}

	// Tier 2: mongosh/mongo CLI queries
	tier2ok := mongoCollectServerStatus(&inst, secrets, app.Port)
	if tier2ok {
		inst.HasDeepMetrics = true
		mongoCollectWTCache(&inst, secrets, app.Port)
		mongoCollectReplStatus(&inst, secrets, app.Port)
		mongoCollectReplLag(&inst, secrets, app.Port)
		mongoCollectDBStats(&inst, secrets, app.Port)
		mongoCollectSlowOps(&inst, secrets, app.Port)
	} else {
		// CLI not available or auth required
		if secrets == nil || secrets.MongoDB == nil || secrets.MongoDB.URI == "" {
			inst.NeedsCreds = true
		}
	}

	// Health scoring
	inst.HealthScore = 100
	mongoHealthScore(&inst, configCacheSizeGB)

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

// mongoQuery executes a JavaScript expression via mongosh (falling back to mongo).
func mongoQuery(secrets *AppSecrets, port int, jsCode string) (string, error) {
	args := []string{"--quiet", "--eval", jsCode}
	if secrets != nil && secrets.MongoDB != nil && secrets.MongoDB.URI != "" {
		args = append([]string{secrets.MongoDB.URI}, args...)
	} else {
		args = append(args, "--port", fmt.Sprintf("%d", port))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Try mongosh first, fall back to mongo
	cmd := exec.CommandContext(ctx, "mongosh", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		cmd2 := exec.CommandContext(ctx2, "mongo", args...)
		out, err = cmd2.CombinedOutput()
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// extractJSON finds the first {...} JSON object in mongosh output (which may include warnings).
func extractJSON(raw string) string {
	start := strings.Index(raw, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(raw); i++ {
		switch raw[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return raw[start : i+1]
			}
		}
	}
	return ""
}

// mongoCollectServerStatus queries db.serverStatus() and populates deep metrics.
// Returns true if the query succeeded.
func mongoCollectServerStatus(inst *model.AppInstance, secrets *AppSecrets, port int) bool {
	js := `var s=db.serverStatus();JSON.stringify({conn_cur:s.connections.current,conn_avail:s.connections.available,conn_total:s.connections.totalCreated,op_insert:s.opcounters.insert,op_query:s.opcounters.query,op_update:s.opcounters.update,op_delete:s.opcounters.delete,op_command:s.opcounters.command,mem_res:s.mem.resident,mem_virt:s.mem.virtual,lock_queue:s.globalLock.currentQueue.total,lock_readers:s.globalLock.currentQueue.readers,lock_writers:s.globalLock.currentQueue.writers,active_total:s.globalLock.activeClients.total,active_readers:s.globalLock.activeClients.readers,active_writers:s.globalLock.activeClients.writers,version:s.version,storage:s.storageEngine?s.storageEngine.name:"",uptime:s.uptime})`

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return false
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return false
	}

	setMetric := func(key string, val interface{}) {
		switch v := val.(type) {
		case float64:
			if v == float64(int64(v)) {
				inst.DeepMetrics[key] = fmt.Sprintf("%d", int64(v))
			} else {
				inst.DeepMetrics[key] = fmt.Sprintf("%.2f", v)
			}
		case string:
			inst.DeepMetrics[key] = v
		}
	}

	setMetric("conn_current", data["conn_cur"])
	setMetric("conn_available", data["conn_avail"])
	setMetric("conn_total_created", data["conn_total"])
	setMetric("op_insert", data["op_insert"])
	setMetric("op_query", data["op_query"])
	setMetric("op_update", data["op_update"])
	setMetric("op_delete", data["op_delete"])
	setMetric("op_command", data["op_command"])
	setMetric("mem_resident_mb", data["mem_res"])
	setMetric("mem_virtual_mb", data["mem_virt"])
	setMetric("lock_queue_total", data["lock_queue"])
	setMetric("lock_queue_readers", data["lock_readers"])
	setMetric("lock_queue_writers", data["lock_writers"])
	setMetric("active_clients", data["active_total"])
	setMetric("active_readers", data["active_readers"])
	setMetric("active_writers", data["active_writers"])
	setMetric("storage_engine", data["storage"])

	if v, ok := data["version"].(string); ok && v != "" {
		inst.Version = v
		inst.DeepMetrics["version"] = v
	}

	return true
}

// mongoCollectWTCache queries WiredTiger cache stats.
func mongoCollectWTCache(inst *model.AppInstance, secrets *AppSecrets, port int) {
	js := `var s=db.serverStatus().wiredTiger;s?JSON.stringify({cache_used:s.cache["bytes currently in the cache"],cache_max:s.cache["maximum bytes configured"],cache_dirty:s.cache["tracked dirty bytes in the cache"],cache_reads:s.cache["pages read into cache"],cache_writes:s.cache["pages written from cache"]}):"{}"` //nolint:lll

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" || jsonStr == "{}" {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	toMB := func(key string) string {
		if v, ok := data[key].(float64); ok {
			return fmt.Sprintf("%.1f", v/(1024*1024))
		}
		return ""
	}

	if v := toMB("cache_used"); v != "" {
		inst.DeepMetrics["cache_used_mb"] = v
	}
	if v := toMB("cache_max"); v != "" {
		inst.DeepMetrics["cache_max_mb"] = v
	}
	if v := toMB("cache_dirty"); v != "" {
		inst.DeepMetrics["cache_dirty_mb"] = v
	}

	// cache usage percentage
	used, uOK := data["cache_used"].(float64)
	max, mOK := data["cache_max"].(float64)
	if uOK && mOK && max > 0 {
		pct := used / max * 100
		inst.DeepMetrics["cache_usage_pct"] = fmt.Sprintf("%.1f", pct)
	}

	if v, ok := data["cache_reads"].(float64); ok {
		inst.DeepMetrics["cache_reads"] = fmt.Sprintf("%d", int64(v))
	}
	if v, ok := data["cache_writes"].(float64); ok {
		inst.DeepMetrics["cache_writes"] = fmt.Sprintf("%d", int64(v))
	}
}

// mongoCollectReplStatus queries rs.status() for replica set info.
func mongoCollectReplStatus(inst *model.AppInstance, secrets *AppSecrets, port int) {
	js := `var r=rs.status();JSON.stringify({set:r.set,members:r.members.length,myState:r.myState,ok:r.ok})`

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	if v, ok := data["set"].(string); ok && v != "" {
		inst.DeepMetrics["repl_set"] = v
	}
	if v, ok := data["members"].(float64); ok {
		inst.DeepMetrics["repl_members"] = fmt.Sprintf("%d", int(v))
	}
	if v, ok := data["myState"].(float64); ok {
		switch int(v) {
		case 1:
			inst.DeepMetrics["repl_state"] = "PRIMARY"
		case 2:
			inst.DeepMetrics["repl_state"] = "SECONDARY"
		case 7:
			inst.DeepMetrics["repl_state"] = "ARBITER"
		default:
			inst.DeepMetrics["repl_state"] = fmt.Sprintf("state_%d", int(v))
		}
	}
}

// mongoCollectReplLag queries replication lag if this node is a secondary.
func mongoCollectReplLag(inst *model.AppInstance, secrets *AppSecrets, port int) {
	if inst.DeepMetrics["repl_state"] != "SECONDARY" {
		return
	}

	js := `var s=rs.status();var p=s.members.filter(function(m){return m.stateStr=="PRIMARY"})[0];var me=s.members.filter(function(m){return m.self})[0];JSON.stringify({lag_sec:me&&p?(p.optime.ts.getTime()-me.optime.ts.getTime()):0})` //nolint:lll

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	if v, ok := data["lag_sec"].(float64); ok {
		inst.DeepMetrics["repl_lag_sec"] = fmt.Sprintf("%d", int(v))
	}
}

// mongoCollectDBStats queries listDatabases for total storage size.
func mongoCollectDBStats(inst *model.AppInstance, secrets *AppSecrets, port int) {
	js := `var dbs=db.adminCommand({listDatabases:1});JSON.stringify({total_size:dbs.totalSize,db_count:dbs.databases.length})`

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	if v, ok := data["total_size"].(float64); ok {
		inst.DeepMetrics["total_size_mb"] = fmt.Sprintf("%.1f", v/(1024*1024))
	}
	if v, ok := data["db_count"].(float64); ok {
		inst.DeepMetrics["db_count"] = fmt.Sprintf("%d", int(v))
	}
}

// mongoCollectSlowOps queries currentOp for active operations running > 5s.
func mongoCollectSlowOps(inst *model.AppInstance, secrets *AppSecrets, port int) {
	js := `var ops=db.currentOp({active:true,secs_running:{$gt:5}});JSON.stringify({slow_ops:ops.inprog.length})`

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	if v, ok := data["slow_ops"].(float64); ok {
		inst.DeepMetrics["slow_ops"] = fmt.Sprintf("%d", int(v))
	}
}

// parseMongoConfig does simple line-based parsing of mongod.conf for key settings.
// Returns (cacheSizeGB, maxConnections, replSetName).
func parseMongoConfig(path string) (float64, int, string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, ""
	}
	defer f.Close()

	var cacheSizeGB float64
	var maxConns int
	var replSetName string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// cacheSizeGB: 2
		if strings.HasPrefix(line, "cacheSizeGB:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "cacheSizeGB:"))
			cacheSizeGB, _ = strconv.ParseFloat(val, 64)
		}
		// maxIncomingConnections: 65536
		if strings.HasPrefix(line, "maxIncomingConnections:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "maxIncomingConnections:"))
			maxConns, _ = strconv.Atoi(val)
		}
		// replSetName: rs0
		if strings.HasPrefix(line, "replSetName:") {
			replSetName = strings.TrimSpace(strings.TrimPrefix(line, "replSetName:"))
			replSetName = strings.Trim(replSetName, `"'`)
		}
	}

	return cacheSizeGB, maxConns, replSetName
}

// mongoHealthScore applies health penalties based on collected deep metrics.
func mongoHealthScore(inst *model.AppInstance, configCacheSizeGB float64) {
	if !inst.HasDeepMetrics {
		// Only FD-based check for Tier 1
		if inst.FDs > 50000 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("high FD count (%d)", inst.FDs))
		}
		return
	}

	// Connection usage: current / (current + available)
	connCur, _ := strconv.ParseFloat(inst.DeepMetrics["conn_current"], 64)
	connAvail, _ := strconv.ParseFloat(inst.DeepMetrics["conn_available"], 64)
	if connAvail > 0 {
		total := connCur + connAvail
		pct := connCur / total * 100
		if pct > 90 {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("connection usage %.0f%% — near limit", pct))
		} else if pct > 80 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("connection usage %.0f%%", pct))
		}
	}

	// Cache usage > 95%
	if pctStr := inst.DeepMetrics["cache_usage_pct"]; pctStr != "" {
		pct, _ := strconv.ParseFloat(pctStr, 64)
		if pct > 95 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("WT cache usage %.1f%% — eviction pressure", pct))
		}
	}

	// Cache dirty > 20% of cache
	dirtyMB, _ := strconv.ParseFloat(inst.DeepMetrics["cache_dirty_mb"], 64)
	cacheMB, _ := strconv.ParseFloat(inst.DeepMetrics["cache_max_mb"], 64)
	if cacheMB > 0 && dirtyMB > 0 {
		dirtyPct := dirtyMB / cacheMB * 100
		if dirtyPct > 20 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("WT cache %.0f%% dirty — write stalls possible", dirtyPct))
		}
	}

	// Lock queue
	lockQ, _ := strconv.Atoi(inst.DeepMetrics["lock_queue_total"])
	if lockQ > 10 {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("lock queue %d — heavy contention", lockQ))
	} else if lockQ > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("lock queue %d", lockQ))
	}

	// Replication lag
	if lagStr := inst.DeepMetrics["repl_lag_sec"]; lagStr != "" {
		lag, _ := strconv.Atoi(lagStr)
		if lag > 60 {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("replication lag %ds — severely behind primary", lag))
		} else if lag > 10 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("replication lag %ds", lag))
		}
	}

	// Slow operations
	slowOps, _ := strconv.Atoi(inst.DeepMetrics["slow_ops"])
	if slowOps > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d slow operations (>5s)", slowOps))
	}

	// Memory resident vs configured cache
	memRes, _ := strconv.ParseFloat(inst.DeepMetrics["mem_resident_mb"], 64)
	if configCacheSizeGB > 0 && memRes > 0 {
		cacheMBConfig := configCacheSizeGB * 1024
		if memRes > cacheMBConfig*0.9 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("resident memory %.0fMB near configured cache %.0fMB", memRes, cacheMBConfig))
		}
	}

	// FD count
	if inst.FDs > 50000 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high FD count (%d)", inst.FDs))
	}
}
