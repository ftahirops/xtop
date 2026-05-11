//go:build linux

package phpfpm

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// parseStatusFull parses the body PHP-FPM returns for `?full`. The format
// is fixed and well-documented:
//
//	pool:                 www
//	process manager:      dynamic
//	...
//	************************
//	pid:                  1440
//	state:                Idle
//	start time:           ...
//	requests:             484
//	request duration:     42727
//	request method:       GET
//	request URI:          /index.php
//	content length:       0
//	user:                 -
//	script:               /www/wwwroot/new.dula.ai/index.php
//	last request cpu:     117.02
//	last request memory:  20971520
//
// Each `************************` line introduces one worker block.
func parseStatusFull(body []byte, masterPID int, phpVersion string) (poolName string, workers []model.PHPFPMWorker) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)

	var cur model.PHPFPMWorker
	inWorker := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "***") {
			if inWorker {
				workers = append(workers, cur)
			}
			cur = model.PHPFPMWorker{
				MasterPID:  masterPID,
				PHPVersion: phpVersion,
				PoolName:   poolName,
			}
			inWorker = true
			continue
		}
		k, v, ok := splitColon(line)
		if !ok {
			continue
		}
		if !inWorker {
			// Pool-level fields (we only need the pool name).
			if k == "pool" {
				poolName = v
			}
			continue
		}
		cur.PoolName = poolName
		switch k {
		case "pid":
			cur.PID, _ = strconv.Atoi(v)
		case "state":
			cur.State = v
		case "request method":
			cur.RequestMethod = v
		case "request uri":
			cur.RequestURI = v
		case "script":
			if v != "-" {
				cur.Script = v
				cur.App = appFromScript(v)
			}
		case "request duration":
			cur.DurationUs, _ = strconv.ParseInt(v, 10, 64)
		case "requests":
			cur.RequestsTotal, _ = strconv.ParseInt(v, 10, 64)
		case "last request cpu":
			cur.LastReqCPUPct, _ = strconv.ParseFloat(v, 64)
		case "last request memory":
			cur.LastReqMemKB, _ = strconv.ParseInt(v, 10, 64)
			cur.LastReqMemKB /= 1024
		}
	}
	if inWorker {
		workers = append(workers, cur)
	}
	return poolName, workers
}

// splitColon is like splitKV but for "key:    value" lines. PHP-FPM's
// status uses colon-separated, multi-space-padded output.
func splitColon(s string) (k, v string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	k = strings.TrimSpace(strings.ToLower(s[:i]))
	v = strings.TrimSpace(s[i+1:])
	return k, v, k != ""
}

// appFromScript turns a script path into a friendly app name:
//
//	/www/wwwroot/new.dula.ai/index.php           → "new.dula.ai"
//	/var/www/html/wordpress/index.php            → "wordpress"
//	/srv/http/site.example.com/public/index.php  → "site.example.com"
//
// Heuristic: walk up the path until we hit a "well-known web root" dir
// (wwwroot, html, www, sites, htdocs, http, vhosts) and use the next
// component as the app name. Fall back to the parent directory of the
// script if no marker matches.
func appFromScript(p string) string {
	if p == "" {
		return ""
	}
	parts := strings.Split(filepath.Clean(p), string(filepath.Separator))
	markers := map[string]bool{
		"wwwroot": true,
		"html":    true,
		"www":     true,
		"sites":   true,
		"htdocs":  true,
		"http":    true,
		"vhosts":  true,
	}
	// Walk from the leaf upward so the *deepest* marker wins — this
	// gives /www/wwwroot/new.dula.ai/index.php → "new.dula.ai" instead
	// of getting fooled by the "www" parent dir.
	for i := len(parts) - 2; i >= 0; i-- {
		if markers[parts[i]] && i+1 < len(parts) {
			next := parts[i+1]
			if next != "" && !strings.HasSuffix(next, ".php") {
				return next
			}
		}
	}
	// Fallback: parent dir name.
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return filepath.Base(p)
}
