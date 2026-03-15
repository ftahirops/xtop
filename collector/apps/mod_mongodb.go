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

// collPrev stores previous per-collection counters for delta computation.
// [r_ops, w_ops, r_lat_us, w_lat_us]
type collPrev [4]int64

type mongoModule struct {
	prevColl map[string]collPrev // key: "db.coll"
	prevTime time.Time
}

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

// mongoConfig holds parsed settings from mongod.conf.
type mongoConfig struct {
	CacheSizeGB    float64
	MaxConns       int
	ReplSetName    string
	BindIP         string
	Authorization  string
	TLSMode        string
	Journal        string
	ProfilingLevel int
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

	var cfg mongoConfig
	if inst.ConfigPath != "" {
		cfg = parseMongoConfig(inst.ConfigPath)
		if cfg.CacheSizeGB > 0 {
			inst.DeepMetrics["wt_cache_size_gb"] = fmt.Sprintf("%.1f", cfg.CacheSizeGB)
		}
		if cfg.MaxConns > 0 {
			inst.DeepMetrics["max_connections"] = fmt.Sprintf("%d", cfg.MaxConns)
		}
		if cfg.ReplSetName != "" {
			inst.DeepMetrics["config_repl_set"] = cfg.ReplSetName
		}
		if cfg.BindIP != "" {
			inst.DeepMetrics["bind_ip"] = cfg.BindIP
		}
		if cfg.Authorization != "" {
			inst.DeepMetrics["auth_enabled"] = cfg.Authorization
		}
		if cfg.TLSMode != "" {
			inst.DeepMetrics["tls_mode"] = cfg.TLSMode
		}
		if cfg.Journal != "" {
			inst.DeepMetrics["journal"] = cfg.Journal
		}
		if cfg.ProfilingLevel > 0 {
			inst.DeepMetrics["profiling_level"] = fmt.Sprintf("%d", cfg.ProfilingLevel)
		}
	}

	// Tier 2: mongosh/mongo CLI queries
	tier2ok := mongoCollectServerStatus(&inst, secrets, app.Port)
	if tier2ok {
		inst.HasDeepMetrics = true
		mongoCollectWTCache(&inst, secrets, app.Port)
		mongoCollectWTTickets(&inst, secrets, app.Port)
		mongoCollectReplStatus(&inst, secrets, app.Port)
		mongoCollectReplLag(&inst, secrets, app.Port)
		m.mongoCollectPerDBStats(&inst, secrets, app.Port)
		mongoCollectCurrentOps(&inst, secrets, app.Port)
	} else {
		// CLI not available or auth required
		if secrets == nil || secrets.MongoDB == nil || secrets.MongoDB.URI == "" {
			inst.NeedsCreds = true
		}
	}

	// Health scoring
	inst.HealthScore = 100
	mongoHealthScore(&inst, cfg.CacheSizeGB)

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
// Returns true if the query succeeded. Also extracts network, document, cursor,
// assert, and page fault metrics in the same call.
func mongoCollectServerStatus(inst *model.AppInstance, secrets *AppSecrets, port int) bool {
	// Use Number() to convert MongoDB 8.0 NumberLong objects to plain numbers
	js := `var s=db.serverStatus();JSON.stringify({` +
		`conn_cur:Number(s.connections.current),conn_avail:Number(s.connections.available),conn_total:Number(s.connections.totalCreated),` +
		`conn_rejected:Number(s.connections.rejected||0),conn_active:Number(s.connections.active||0),` +
		`op_insert:Number(s.opcounters.insert),op_query:Number(s.opcounters.query),op_update:Number(s.opcounters.update),` +
		`op_delete:Number(s.opcounters.delete),op_command:Number(s.opcounters.command),op_getmore:Number(s.opcounters.getmore),` +
		`mem_res:Number(s.mem.resident),mem_virt:Number(s.mem.virtual),` +
		`lock_queue:Number(s.globalLock.currentQueue.total),lock_readers:Number(s.globalLock.currentQueue.readers),` +
		`lock_writers:Number(s.globalLock.currentQueue.writers),` +
		`active_total:Number(s.globalLock.activeClients.total),active_readers:Number(s.globalLock.activeClients.readers),` +
		`active_writers:Number(s.globalLock.activeClients.writers),` +
		`version:s.version,storage:s.storageEngine?s.storageEngine.name:"",uptime:Number(s.uptime),` +
		// Network metrics
		`net_in:Number(s.network.bytesIn),net_out:Number(s.network.bytesOut),net_reqs:Number(s.network.numRequests),` +
		// Document metrics
		`doc_ins:Number(s.metrics.document.inserted),doc_ret:Number(s.metrics.document.returned),` +
		`doc_upd:Number(s.metrics.document.updated),doc_del:Number(s.metrics.document.deleted),` +
		// Cursor metrics
		`cur_open:Number(s.metrics.cursor.open.total),cur_timeout:Number(s.metrics.cursor.timedOut),` +
		`cur_noTimeout:Number(s.metrics.cursor.open.noTimeout),` +
		// Assert metrics
		`assert_reg:Number(s.asserts.regular),assert_warn:Number(s.asserts.warning),` +
		`assert_msg:Number(s.asserts.msg),assert_user:Number(s.asserts.user),assert_roll:Number(s.asserts.rollovers),` +
		// Page faults
		`page_faults:Number(s.extra_info.page_faults),` +
		// Query executor stats
		`scanned:Number(s.metrics.queryExecutor.scanned),scanned_obj:Number(s.metrics.queryExecutor.scannedObjects),` +
		`coll_scans:Number(s.metrics.queryExecutor.collectionScans.total),` +
		// Operation stats
		`killed_disconnect:Number(s.metrics.operation.killedDueToClientDisconnect),` +
		`killed_maxtime:Number(s.metrics.operation.killedDueToMaxTimeMSExpired),` +
		`scan_and_order:Number(s.metrics.operation.scanAndOrder),` +
		// Global latency
		`lat_r_ops:Number(s.opLatencies.reads.ops),lat_r_us:Number(s.opLatencies.reads.latency),` +
		`lat_w_ops:Number(s.opLatencies.writes.ops),lat_w_us:Number(s.opLatencies.writes.latency),` +
		`lat_c_ops:Number(s.opLatencies.commands.ops),lat_c_us:Number(s.opLatencies.commands.latency),` +
		// TTL
		`ttl_deleted:Number(s.metrics.ttl.deletedDocuments),ttl_passes:Number(s.metrics.ttl.passes)` +
		`})`

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
		case map[string]interface{}:
			// MongoDB 8.0 NumberLong: {"high":N,"low":N,"unsigned":bool}
			hi, _ := v["high"].(float64)
			lo, _ := v["low"].(float64)
			val := int64(hi)*4294967296 + int64(lo)
			inst.DeepMetrics[key] = fmt.Sprintf("%d", val)
		}
	}

	// Original serverStatus metrics
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

	// Network metrics
	setMetric("net_bytes_in", data["net_in"])
	setMetric("net_bytes_out", data["net_out"])
	setMetric("net_num_requests", data["net_reqs"])

	// Document metrics
	setMetric("doc_inserted", data["doc_ins"])
	setMetric("doc_returned", data["doc_ret"])
	setMetric("doc_updated", data["doc_upd"])
	setMetric("doc_deleted", data["doc_del"])

	// Cursor metrics
	setMetric("cursor_open", data["cur_open"])
	setMetric("cursor_timed_out", data["cur_timeout"])
	setMetric("cursor_no_timeout", data["cur_noTimeout"])

	// Assert metrics
	setMetric("assert_regular", data["assert_reg"])
	setMetric("assert_warning", data["assert_warn"])
	setMetric("assert_msg", data["assert_msg"])
	setMetric("assert_user", data["assert_user"])
	setMetric("assert_rollovers", data["assert_roll"])

	// Page faults
	setMetric("page_faults", data["page_faults"])

	// Additional connections
	setMetric("conn_rejected", data["conn_rejected"])
	setMetric("conn_active", data["conn_active"])
	setMetric("op_getmore", data["op_getmore"])

	// Query executor
	setMetric("scanned_keys", data["scanned"])
	setMetric("scanned_objects", data["scanned_obj"])
	setMetric("collection_scans", data["coll_scans"])

	// Operation stats
	setMetric("killed_disconnect", data["killed_disconnect"])
	setMetric("killed_maxtime", data["killed_maxtime"])
	setMetric("scan_and_order", data["scan_and_order"])

	// Global latency (compute avg in µs)
	latROps, _ := data["lat_r_ops"].(float64)
	latRUs, _ := data["lat_r_us"].(float64)
	latWOps, _ := data["lat_w_ops"].(float64)
	latWUs, _ := data["lat_w_us"].(float64)
	if latROps > 0 {
		inst.DeepMetrics["avg_read_latency_us"] = fmt.Sprintf("%d", int64(latRUs/latROps))
	}
	if latWOps > 0 {
		inst.DeepMetrics["avg_write_latency_us"] = fmt.Sprintf("%d", int64(latWUs/latWOps))
	}
	setMetric("total_read_ops", data["lat_r_ops"])
	setMetric("total_write_ops", data["lat_w_ops"])

	// TTL
	setMetric("ttl_deleted", data["ttl_deleted"])
	setMetric("ttl_passes", data["ttl_passes"])

	return true
}

// mongoCollectWTCache queries WiredTiger cache stats.
func mongoCollectWTCache(inst *model.AppInstance, secrets *AppSecrets, port int) {
	js := `var s=db.serverStatus().wiredTiger;s?JSON.stringify({cache_used:Number(s.cache["bytes currently in the cache"]),cache_max:Number(s.cache["maximum bytes configured"]),cache_dirty:Number(s.cache["tracked dirty bytes in the cache"]),cache_reads:Number(s.cache["pages read into cache"]),cache_writes:Number(s.cache["pages written from cache"])}):"{}"` //nolint:lll

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
		switch v := data[key].(type) {
		case float64:
			return fmt.Sprintf("%.1f", v/(1024*1024))
		case map[string]interface{}:
			hi, _ := v["high"].(float64)
			lo, _ := v["low"].(float64)
			val := int64(hi)*4294967296 + int64(lo)
			return fmt.Sprintf("%.1f", float64(val)/(1024*1024))
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

	// cache usage percentage — handle both float64 and NumberLong
	mongoFloat := func(v interface{}) (float64, bool) {
		switch x := v.(type) {
		case float64:
			return x, true
		case map[string]interface{}:
			hi, _ := x["high"].(float64)
			lo, _ := x["low"].(float64)
			return float64(int64(hi)*4294967296 + int64(lo)), true
		}
		return 0, false
	}
	used, uOK := mongoFloat(data["cache_used"])
	max, mOK := mongoFloat(data["cache_max"])
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

// mongoCollectWTTickets queries WiredTiger concurrent transaction ticket stats.
func mongoCollectWTTickets(inst *model.AppInstance, secrets *AppSecrets, port int) {
	js := `var s=db.serverStatus().wiredTiger;if(!s||!s.concurrentTransactions)print("{}");else JSON.stringify({` +
		`r_avail:Number(s.concurrentTransactions.read.available),` +
		`r_out:Number(s.concurrentTransactions.read.out),` +
		`w_avail:Number(s.concurrentTransactions.write.available),` +
		`w_out:Number(s.concurrentTransactions.write.out)` +
		`})` //nolint:lll

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

	setInt := func(key string, val interface{}) {
		if v, ok := val.(float64); ok {
			inst.DeepMetrics[key] = fmt.Sprintf("%d", int64(v))
		}
	}

	setInt("wt_read_avail", data["r_avail"])
	setInt("wt_read_out", data["r_out"])
	setInt("wt_write_avail", data["w_avail"])
	setInt("wt_write_out", data["w_out"])
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

// mongoCollectPerDBStats queries listDatabases with per-database and per-collection
// details including latency stats from $collStats (reads/writes/commands ops and avg latency).
func (m *mongoModule) mongoCollectPerDBStats(inst *model.AppInstance, secrets *AppSecrets, port int) {
	js := `var d=db.adminCommand({listDatabases:1});var result=[];` +
		`d.databases.forEach(function(x){` +
		`var tmp=db.getSiblingDB(x.name);` +
		`var cnames=tmp.getCollectionNames();` +
		`var colls=[];` +
		`cnames.forEach(function(c){` +
		`if(c.startsWith("system."))return;` +
		`var st=tmp.getCollection(c).stats();` +
		`var idxs=tmp.getCollection(c).getIndexes();` +
		`var inames=idxs.map(function(i){return i.name});` +
		`var lat={r_ops:0,r_lat:0,w_ops:0,w_lat:0,c_ops:0,c_lat:0};` +
		`try{var cs=tmp.getCollection(c).aggregate([{$collStats:{latencyStats:{histograms:false}}}]).toArray();` +
		`if(cs.length>0&&cs[0].latencyStats){var ls=cs[0].latencyStats;` +
		`lat.r_ops=Number(ls.reads.ops||0);lat.r_lat=Number(ls.reads.latency||0);` +
		`lat.w_ops=Number(ls.writes.ops||0);lat.w_lat=Number(ls.writes.latency||0);` +
		`lat.c_ops=Number(ls.commands.ops||0);lat.c_lat=Number(ls.commands.latency||0)}}catch(e){}` +
		`colls.push({name:c,size_mb:Number(st.size||0)/(1024*1024),docs:Number(st.count||0),` +
		`indexes:idxs.length,idx_names:inames,avg_obj:Number(st.avgObjSize||0),` +
		`r_ops:lat.r_ops,r_lat:lat.r_lat,w_ops:lat.w_ops,w_lat:lat.w_lat,` +
		`c_ops:lat.c_ops,c_lat:lat.c_lat})` +
		`});` +
		`result.push({name:x.name,size_mb:Number(x.sizeOnDisk)/(1024*1024),` +
		`collections:cnames.length,colls:colls})` +
		`});JSON.stringify({total_size:Number(d.totalSize),db_count:d.databases.length,dbs:result})`

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return
	}

	var data struct {
		TotalSize float64 `json:"total_size"`
		DBCount   float64 `json:"db_count"`
		DBs       []struct {
			Name        string  `json:"name"`
			SizeMB      float64 `json:"size_mb"`
			Collections float64 `json:"collections"`
			Colls       []struct {
				Name     string   `json:"name"`
				SizeMB   float64  `json:"size_mb"`
				Docs     float64  `json:"docs"`
				Indexes  float64  `json:"indexes"`
				IdxNames []string `json:"idx_names"`
				AvgObj   float64  `json:"avg_obj"`
				ROps     float64  `json:"r_ops"`
				RLat     float64  `json:"r_lat"`
				WOps     float64  `json:"w_ops"`
				WLat     float64  `json:"w_lat"`
				COps     float64  `json:"c_ops"`
				CLat     float64  `json:"c_lat"`
			} `json:"colls"`
		} `json:"dbs"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	inst.DeepMetrics["total_size_mb"] = fmt.Sprintf("%.1f", data.TotalSize/(1024*1024))
	inst.DeepMetrics["db_count"] = fmt.Sprintf("%d", int(data.DBCount))

	// Build per-db JSON with collection details + delta-based latency + rates
	now := time.Now()
	elapsed := now.Sub(m.prevTime).Seconds()
	newColl := make(map[string]collPrev)

	var names []string
	type collEntry struct {
		Name      string   `json:"name"`
		SizeMB    float64  `json:"size_mb"`
		Docs      int64    `json:"docs"`
		Indexes   int      `json:"indexes"`
		IdxNames  []string `json:"idx_names"`
		AvgObj    int      `json:"avg_obj"`
		ROps      int64    `json:"r_ops"`
		RAvgUs    int64    `json:"r_avg_us"`
		WOps      int64    `json:"w_ops"`
		WAvgUs    int64    `json:"w_avg_us"`
		COps      int64    `json:"c_ops"`
		CAvgUs    int64    `json:"c_avg_us"`
		ROpsRate  float64  `json:"r_ops_rate,omitempty"`
		WOpsRate  float64  `json:"w_ops_rate,omitempty"`
	}
	type dbEntry struct {
		Name        string      `json:"name"`
		SizeMB      float64     `json:"size_mb"`
		Collections int         `json:"collections"`
		Indexes     int         `json:"indexes"`
		Colls       []collEntry `json:"colls"`
	}
	var entries []dbEntry
	for _, d := range data.DBs {
		names = append(names, d.Name)
		var colls []collEntry
		totalIdx := 0
		for _, c := range d.Colls {
			totalIdx += int(c.Indexes)

			collKey := d.Name + "." + c.Name
			rOps := int64(c.ROps)
			wOps := int64(c.WOps)
			rLat := int64(c.RLat)
			wLat := int64(c.WLat)
			newColl[collKey] = collPrev{rOps, wOps, rLat, wLat}

			// Delta-based avg latency: (curr_lat - prev_lat) / (curr_ops - prev_ops)
			// This gives real-time avg latency for the current interval only.
			// Falls back to lifetime avg on first tick.
			var rAvg, wAvg, cAvg int64
			if m.prevColl != nil && elapsed > 0 {
				if prev, ok := m.prevColl[collKey]; ok {
					dROps := rOps - prev[0]
					dWOps := wOps - prev[1]
					dRLat := rLat - prev[2]
					dWLat := wLat - prev[3]
					if dROps > 0 && dRLat >= 0 {
						rAvg = dRLat / dROps
					}
					if dWOps > 0 && dWLat >= 0 {
						wAvg = dWLat / dWOps
					}
				}
			} else {
				// First tick: lifetime average
				if rOps > 0 {
					rAvg = rLat / rOps
				}
				if wOps > 0 {
					wAvg = wLat / wOps
				}
			}
			if c.COps > 0 {
				cAvg = int64(c.CLat / c.COps)
			}

			// Rate computation
			var rRate, wRate float64
			if m.prevColl != nil && elapsed > 0 {
				if prev, ok := m.prevColl[collKey]; ok {
					if rOps >= prev[0] {
						rRate = float64(rOps-prev[0]) / elapsed
					}
					if wOps >= prev[1] {
						wRate = float64(wOps-prev[1]) / elapsed
					}
				}
			}

			colls = append(colls, collEntry{
				Name:     c.Name,
				SizeMB:   c.SizeMB,
				Docs:     int64(c.Docs),
				Indexes:  int(c.Indexes),
				IdxNames: c.IdxNames,
				AvgObj:   int(c.AvgObj),
				ROps:     rOps,
				RAvgUs:   rAvg,
				WOps:     wOps,
				WAvgUs:   wAvg,
				COps:     int64(c.COps),
				CAvgUs:   cAvg,
				ROpsRate: rRate,
				WOpsRate: wRate,
			})
		}
		entries = append(entries, dbEntry{
			Name:        d.Name,
			SizeMB:      d.SizeMB,
			Collections: int(d.Collections),
			Indexes:     totalIdx,
			Colls:       colls,
		})
	}

	m.prevColl = newColl
	m.prevTime = now

	if listJSON, err := json.Marshal(entries); err == nil {
		inst.DeepMetrics["db_list"] = string(listJSON)
	}
	inst.DeepMetrics["db_names"] = strings.Join(names, ",")
}

// mongoCollectCurrentOps queries currentOp for active and slow operations.
// Captures the top slow queries with their details for display.
func mongoCollectCurrentOps(inst *model.AppInstance, secrets *AppSecrets, port int) {
	// Enhanced: also collect per-client connection counts and op type breakdown
	js := `var ops=db.currentOp();var slow=ops.inprog.filter(function(o){return o.active&&o.secs_running>5});` +
		`slow.sort(function(a,b){return (b.secs_running||0)-(a.secs_running||0)});` +
		`var top=slow.slice(0,10).map(function(o){` +
		`var cmd="";if(o.command){try{cmd=JSON.stringify(o.command).substring(0,200)}catch(e){}}` +
		`return {op:o.op||"",ns:o.ns||"",secs:o.secs_running||0,client:o.client||"",` +
		`plan:o.planSummary||"",cmd:cmd}});` +
		// Per-client IP connection counts
		`var clients={};var opTypes={};` +
		`ops.inprog.forEach(function(o){` +
		`var ip=(o.client||"").split(":")[0];if(ip)clients[ip]=(clients[ip]||0)+1;` +
		`var ot=o.op||"none";opTypes[ot]=(opTypes[ot]||0)+1;` +
		`if(o.active&&o.command&&o.command.hello)opTypes["hello"]=(opTypes["hello"]||0)+1;` +
		`if(o.active&&o.command&&o.command.isMaster)opTypes["hello"]=(opTypes["hello"]||0)+1;` +
		`});` +
		// Top clients by connection count
		`var clist=Object.keys(clients).map(function(k){return {ip:k,n:clients[k]}});` +
		`clist.sort(function(a,b){return b.n-a.n});` +
		`JSON.stringify({total:ops.inprog.length,` +
		`active:ops.inprog.filter(function(o){return o.active}).length,` +
		`slow:slow.length,top:top,clients:clist.slice(0,15),op_types:opTypes})`

	raw, err := mongoQuery(secrets, port, js)
	if err != nil {
		return
	}
	jsonStr := extractJSON(raw)
	if jsonStr == "" {
		return
	}

	var data struct {
		Total   float64 `json:"total"`
		Active  float64 `json:"active"`
		Slow    float64 `json:"slow"`
		Top     []struct {
			Op     string  `json:"op"`
			NS     string  `json:"ns"`
			Secs   float64 `json:"secs"`
			Client string  `json:"client"`
			Plan   string  `json:"plan"`
			Cmd    string  `json:"cmd"`
		} `json:"top"`
		Clients []struct {
			IP string  `json:"ip"`
			N  float64 `json:"n"`
		} `json:"clients"`
		OpTypes map[string]float64 `json:"op_types"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	inst.DeepMetrics["current_ops_total"] = fmt.Sprintf("%d", int(data.Total))
	inst.DeepMetrics["current_ops_active"] = fmt.Sprintf("%d", int(data.Active))
	inst.DeepMetrics["slow_ops"] = fmt.Sprintf("%d", int(data.Slow))

	// Store per-client connection breakdown
	if len(data.Clients) > 0 {
		type clientEntry struct {
			IP    string `json:"ip"`
			Count int    `json:"count"`
		}
		var clients []clientEntry
		for _, c := range data.Clients {
			clients = append(clients, clientEntry{IP: c.IP, Count: int(c.N)})
		}
		if j, err := json.Marshal(clients); err == nil {
			inst.DeepMetrics["client_connections"] = string(j)
		}
	}

	// Store operation type breakdown
	if len(data.OpTypes) > 0 {
		type opEntry struct {
			Op    string `json:"op"`
			Count int    `json:"count"`
		}
		var ops2 []opEntry
		for k, v := range data.OpTypes {
			ops2 = append(ops2, opEntry{Op: k, Count: int(v)})
		}
		if j, err := json.Marshal(ops2); err == nil {
			inst.DeepMetrics["op_type_breakdown"] = string(j)
		}
	}

	// Store top slow queries as JSON for UI rendering
	if len(data.Top) > 0 {
		type slowQuery struct {
			Op     string `json:"op"`
			NS     string `json:"ns"`
			Secs   int    `json:"secs"`
			Client string `json:"client"`
			Plan   string `json:"plan"`
			Cmd    string `json:"cmd"`
		}
		var queries []slowQuery
		for _, t := range data.Top {
			queries = append(queries, slowQuery{
				Op:     t.Op,
				NS:     t.NS,
				Secs:   int(t.Secs),
				Client: t.Client,
				Plan:   t.Plan,
				Cmd:    t.Cmd,
			})
		}
		if j, err := json.Marshal(queries); err == nil {
			inst.DeepMetrics["slow_queries"] = string(j)
		}
	}
}

// parseMongoConfig does line-based parsing of mongod.conf for key settings.
// Returns a mongoConfig struct with all parsed values.
func parseMongoConfig(path string) mongoConfig {
	var cfg mongoConfig

	f, err := os.Open(path)
	if err != nil {
		return cfg
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// cacheSizeGB: 2
		if strings.HasPrefix(line, "cacheSizeGB:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "cacheSizeGB:"))
			cfg.CacheSizeGB, _ = strconv.ParseFloat(val, 64)
		}
		// maxIncomingConnections: 65536
		if strings.HasPrefix(line, "maxIncomingConnections:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "maxIncomingConnections:"))
			cfg.MaxConns, _ = strconv.Atoi(val)
		}
		// replSetName: rs0
		if strings.HasPrefix(line, "replSetName:") {
			cfg.ReplSetName = strings.TrimSpace(strings.TrimPrefix(line, "replSetName:"))
			cfg.ReplSetName = strings.Trim(cfg.ReplSetName, `"'`)
		}
		// bindIp: 127.0.0.1  or  bindIp: 0.0.0.0
		if strings.HasPrefix(line, "bindIp:") {
			cfg.BindIP = strings.TrimSpace(strings.TrimPrefix(line, "bindIp:"))
			cfg.BindIP = strings.Trim(cfg.BindIP, `"'`)
		}
		// authorization: enabled
		if strings.HasPrefix(line, "authorization:") {
			cfg.Authorization = strings.TrimSpace(strings.TrimPrefix(line, "authorization:"))
			cfg.Authorization = strings.Trim(cfg.Authorization, `"'`)
		}
		// mode: requireTLS  (under net.tls)
		// tls mode or ssl mode — match both patterns
		if strings.HasPrefix(line, "mode:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
			val = strings.Trim(val, `"'`)
			// Only set if it looks like a TLS/SSL mode value
			switch val {
			case "disabled", "allowTLS", "preferTLS", "requireTLS",
				"allowSSL", "preferSSL", "requireSSL":
				cfg.TLSMode = val
			}
		}
		// journal.enabled: true / enabled: true (under storage.journal)
		if strings.HasPrefix(line, "enabled:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "enabled:"))
			val = strings.Trim(val, `"'`)
			if val == "true" || val == "false" {
				// Only set journal if not already set (first "enabled:" wins for journal)
				if cfg.Journal == "" {
					cfg.Journal = val
				}
			}
		}
		// profile: 1
		if strings.HasPrefix(line, "profile:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "profile:"))
			cfg.ProfilingLevel, _ = strconv.Atoi(val)
		}
	}

	return cfg
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

	// Connection count thresholds
	if connCur > 10000 {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("very high connection count (%.0f)", connCur))
	} else if connCur > 5000 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high connection count (%.0f)", connCur))
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

	// WiredTiger ticket exhaustion
	wtReadAvail, _ := strconv.Atoi(inst.DeepMetrics["wt_read_avail"])
	wtWriteAvail, _ := strconv.Atoi(inst.DeepMetrics["wt_write_avail"])
	if inst.DeepMetrics["wt_read_avail"] != "" {
		if wtReadAvail < 5 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("WT read tickets critically low (%d avail)", wtReadAvail))
		} else if wtReadAvail < 10 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("WT read tickets low (%d avail)", wtReadAvail))
		}
	}
	if inst.DeepMetrics["wt_write_avail"] != "" {
		if wtWriteAvail < 5 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("WT write tickets critically low (%d avail)", wtWriteAvail))
		} else if wtWriteAvail < 10 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("WT write tickets low (%d avail)", wtWriteAvail))
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

	// Asserts: regular or msg > 0 is concerning
	assertReg, _ := strconv.Atoi(inst.DeepMetrics["assert_regular"])
	assertMsg, _ := strconv.Atoi(inst.DeepMetrics["assert_msg"])
	if assertReg > 0 || assertMsg > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("asserts detected (regular:%d msg:%d)", assertReg, assertMsg))
	}

	// Cursor timeouts
	curTimeout, _ := strconv.Atoi(inst.DeepMetrics["cursor_timed_out"])
	if curTimeout > 100 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("cursor timeouts high (%d)", curTimeout))
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

	// Security note (informational — no score penalty)
	if auth := inst.DeepMetrics["auth_enabled"]; auth == "disabled" {
		inst.HealthIssues = append(inst.HealthIssues, "security: authorization is disabled")
	}
}
