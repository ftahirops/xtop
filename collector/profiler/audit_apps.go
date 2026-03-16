//go:build linux

package profiler

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func auditApps(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule

	for _, app := range snap.Global.Apps.Instances {
		switch app.AppType {
		case "mysql":
			result = append(result, auditMySQL(app, snap)...)
		case "nginx":
			result = append(result, auditNginx(app, snap)...)
		case "haproxy":
			result = append(result, auditHAProxy(app, snap)...)
		case "php-fpm":
			result = append(result, auditPHPFPM(app, snap)...)
		case "redis":
			result = append(result, auditRedis(app, snap)...)
		case "postgresql":
			result = append(result, auditPostgres(app, snap)...)
		}
	}

	return result
}

func auditMySQL(app model.AppInstance, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule
	dm := app.DeepMetrics
	if dm == nil {
		return nil
	}

	totalMB := float64(snap.Global.Memory.Total) / (1024 * 1024)

	// innodb_buffer_pool_size
	if bpStr, ok := dm["innodb_buffer_pool_size"]; ok {
		bp, _ := strconv.ParseFloat(bpStr, 64)
		bpMB := bp / (1024 * 1024)
		bpPct := bpMB / totalMB * 100

		var recPct float64
		switch {
		case snap.Global.Apps.Instances != nil && len(snap.Global.Apps.Instances) > 3:
			recPct = 50 // shared server
		default:
			recPct = 70 // dedicated DB
		}

		status := model.RulePass
		if bpPct < recPct/2 {
			status = model.RuleFail
		} else if bpPct < recPct*0.8 {
			status = model.RuleWarn
		}

		result = append(result, model.AuditRule{
			Domain:      model.OptDomainApps,
			Name:        "mysql.innodb_buffer_pool_size",
			Description: "InnoDB buffer pool size (% of total RAM)",
			Current:     fmt.Sprintf("%.0fM (%.0f%% of RAM)", bpMB, bpPct),
			Recommended: fmt.Sprintf("%.0f%% of RAM (~%.0fM)", recPct, totalMB*recPct/100),
			Impact:      "Database reads hit disk instead of cache",
			Status:      status,
			Weight:      10,
		})
	}

	// max_connections
	if mcStr, ok := dm["max_connections"]; ok {
		mc, _ := strconv.Atoi(mcStr)
		status := model.RulePass
		if mc > 500 {
			status = model.RuleWarn
		}
		if mc > 1000 {
			status = model.RuleFail
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainApps,
			Name:        "mysql.max_connections",
			Description: "MySQL maximum allowed connections",
			Current:     mcStr,
			Recommended: "100-300 (use connection pooling for more)",
			Impact:      "Each connection uses ~10MB RAM; too many causes OOM",
			Status:      status,
			Weight:      5,
		})
	}

	// query_cache (deprecated in MySQL 8, harmful if on)
	if qcStr, ok := dm["query_cache_type"]; ok {
		if qcStr != "OFF" && qcStr != "0" {
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainApps,
				Name:        "mysql.query_cache",
				Description: "Query cache (deprecated, causes lock contention)",
				Current:     "ON",
				Recommended: "OFF (deprecated since MySQL 5.7, removed in 8.0)",
				Impact:      "Global mutex contention on every query",
				Status:      model.RuleFail,
				Weight:      8,
			})
		}
	}

	// slow_query_log
	if sqlStr, ok := dm["slow_query_log"]; ok {
		if sqlStr == "OFF" || sqlStr == "0" {
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainApps,
				Name:        "mysql.slow_query_log",
				Description: "MySQL slow query logging",
				Current:     "disabled",
				Recommended: "enabled (for performance monitoring)",
				Impact:      "Cannot identify slow queries causing performance issues",
				Status:      model.RuleWarn,
				Weight:      3,
			})
		}
	}

	return result
}

func auditNginx(app model.AppInstance, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule
	dm := app.DeepMetrics
	if dm == nil {
		return nil
	}

	// worker_connections vs FD limit
	if wc, ok := dm["worker_connections"]; ok {
		v, _ := strconv.Atoi(wc)
		status := model.RulePass
		if v < 4096 {
			status = model.RuleWarn
		}
		if v < 1024 {
			status = model.RuleFail
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainApps,
			Name:        "nginx.worker_connections",
			Description: "Nginx worker_connections (max concurrent connections per worker)",
			Current:     wc,
			Recommended: ">=4096",
			Impact:      "Connection limit reached under moderate traffic",
			Status:      status,
			Weight:      8,
		})
	}

	return result
}

func auditHAProxy(app model.AppInstance, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule
	dm := app.DeepMetrics
	if dm == nil {
		return nil
	}

	// Check if HA (keepalived)
	haDetected := false
	for _, p := range snap.Processes {
		if p.Comm == "keepalived" {
			haDetected = true
			break
		}
	}

	if !haDetected {
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainApps,
			Name:        "haproxy.ha",
			Description: "High Availability (keepalived/VRRP)",
			Current:     "not detected",
			Recommended: "keepalived for failover",
			Impact:      "Single point of failure — proxy down = full outage",
			Status:      model.RuleWarn,
			Weight:      10,
		})
	}

	// Check server error rates
	if errStr, ok := dm["response_errors"]; ok {
		errs, _ := strconv.Atoi(errStr)
		if totStr, ok := dm["request_total"]; ok {
			tot, _ := strconv.Atoi(totStr)
			if tot > 0 {
				errPct := float64(errs) / float64(tot) * 100
				status := model.RulePass
				if errPct > 1 {
					status = model.RuleFail
				} else if errPct > 0.1 {
					status = model.RuleWarn
				}
				result = append(result, model.AuditRule{
					Domain:      model.OptDomainApps,
					Name:        "haproxy.error_rate",
					Description: "Backend response error rate",
					Current:     fmt.Sprintf("%.2f%%", errPct),
					Recommended: "<0.1%",
					Impact:      "Users experiencing errors from unhealthy backends",
					Status:      status,
					Weight:      8,
				})
			}
		}
	}

	return result
}

func auditPHPFPM(app model.AppInstance, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule

	// Check websites for pool sizing
	for _, ws := range app.Websites {
		if ws.MaxWorkers > 0 && ws.Workers > 0 {
			usePct := float64(ws.Workers) / float64(ws.MaxWorkers) * 100
			if usePct > 80 {
				status := model.RuleFail
				if usePct <= 90 {
					status = model.RuleWarn
				}
				result = append(result, model.AuditRule{
					Domain:      model.OptDomainApps,
					Name:        fmt.Sprintf("phpfpm.pool[%s]", ws.Domain),
					Description: fmt.Sprintf("PHP-FPM pool utilization for %s", ws.Domain),
					Current:     fmt.Sprintf("%d/%d workers (%.0f%%)", ws.Workers, ws.MaxWorkers, usePct),
					Recommended: "<80% utilization",
					Impact:      "Requests queued waiting for free PHP worker",
					Status:      status,
					Weight:      8,
				})
			}
		}
	}

	return result
}

func auditRedis(app model.AppInstance, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule
	dm := app.DeepMetrics
	if dm == nil {
		return nil
	}

	// Check maxmemory-policy
	if policy, ok := dm["maxmemory_policy"]; ok {
		if policy == "noeviction" {
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainApps,
				Name:        "redis.maxmemory_policy",
				Description: "Redis eviction policy when memory limit reached",
				Current:     "noeviction (writes fail at limit)",
				Recommended: "allkeys-lru or volatile-lru",
				Impact:      "Redis returns errors instead of evicting old data",
				Status:      model.RuleWarn,
				Weight:      5,
			})
		}
	}

	// Check persistence
	rdbStr := dm["rdb_last_save_time"]
	aofStr := dm["aof_enabled"]
	if rdbStr == "" && (aofStr == "" || aofStr == "0") {
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainApps,
			Name:        "redis.persistence",
			Description: "Redis data persistence (RDB/AOF)",
			Current:     "no persistence configured",
			Recommended: "RDB snapshots or AOF for durability",
			Impact:      "All data lost on Redis restart",
			Status:      model.RuleWarn,
			Weight:      5,
		})
	}

	// Check if binding to all interfaces
	if bind, ok := dm["bind"]; ok {
		if bind == "" || strings.Contains(bind, "0.0.0.0") {
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainApps,
				Name:        "redis.bind",
				Description: "Redis network binding",
				Current:     "0.0.0.0 (all interfaces)",
				Recommended: "127.0.0.1 (localhost only)",
				Impact:      "Redis accessible from external network without auth",
				Status:      model.RuleFail,
				Weight:      10,
			})
		}
	}

	return result
}

func auditPostgres(app model.AppInstance, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule
	dm := app.DeepMetrics
	if dm == nil {
		return nil
	}

	totalMB := float64(snap.Global.Memory.Total) / (1024 * 1024)

	// shared_buffers
	if sbStr, ok := dm["shared_buffers"]; ok {
		sb, _ := strconv.ParseFloat(sbStr, 64)
		sbMB := sb / (1024 * 1024)
		sbPct := sbMB / totalMB * 100

		status := model.RulePass
		if sbPct < 15 {
			status = model.RuleFail
		} else if sbPct < 20 {
			status = model.RuleWarn
		}

		result = append(result, model.AuditRule{
			Domain:      model.OptDomainApps,
			Name:        "postgres.shared_buffers",
			Description: "PostgreSQL shared_buffers (% of total RAM)",
			Current:     fmt.Sprintf("%.0fM (%.0f%% of RAM)", sbMB, sbPct),
			Recommended: "25% of RAM",
			Impact:      "Suboptimal cache hit ratio, more disk reads",
			Status:      status,
			Weight:      10,
		})
	}

	return result
}
