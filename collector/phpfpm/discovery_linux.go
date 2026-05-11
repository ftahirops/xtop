//go:build linux

// Package phpfpm produces a per-worker view of PHP-FPM by:
//  1. Discovering every running php-fpm master via /proc
//  2. Reading each master's config to learn its listen socket + status path
//  3. Querying status?full over FastCGI to enumerate workers
//  4. Joining workers with /proc/<pid>/stat for live CPU%/RSS
//  5. Bucketing workers by script docroot → per-app aggregate
//
// Cost: ~10-15ms/tick steady-state for a host with 3 PHP versions × 50
// workers. Most expensive step is the FastCGI roundtrip (~2ms per pool).
// Honors SkipDeepProbes when the Resource Guardian is active.
package phpfpm

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// discoverMasters walks /proc and returns one entry per running php-fpm
// master process. We identify a master by:
//   - /proc/<pid>/comm == "php-fpm"
//   - argv contains "master process"
//
// For each master we parse its config to extract listen + status path.
func discoverMasters() []discovered {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []discovered
	for _, e := range procEntries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm := readComm(pid)
		if comm != "php-fpm" && comm != "php-fpm7" && comm != "php-fpm8" {
			continue
		}
		args := readCmdline(pid)
		if !strings.Contains(args, "master process") {
			continue
		}
		cfgPath := extractConfigPath(args)
		if cfgPath == "" {
			cfgPath = guessConfigPath(pid)
		}
		d := discovered{
			pid:        pid,
			configPath: cfgPath,
			phpVersion: phpVersionFromPath(cfgPath),
		}
		parseFPMConfig(cfgPath, &d)
		// Pool config may live in a sibling dir; merge in.
		mergePoolConfigs(cfgPath, &d)
		out = append(out, d)
	}
	return out
}

type discovered struct {
	pid        int
	configPath string
	phpVersion string

	listenAddr string // unix:/tmp/php-cgi-83.sock or 127.0.0.1:9000
	statusPath string // /phpfpm_83_status
	poolName   string
}

// readComm reads /proc/<pid>/comm, trimmed.
func readComm(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readCmdline reads /proc/<pid>/cmdline and replaces NULs with spaces.
// PHP-FPM masters keep argv-style status in cmdline ("master process (...)").
func readCmdline(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	s := string(b)
	s = strings.ReplaceAll(s, "\x00", " ")
	return strings.TrimSpace(s)
}

// extractConfigPath pulls the config path from a master's cmdline.
// PHP-FPM prints "master process (/path/to/php-fpm.conf)" in argv.
func extractConfigPath(args string) string {
	i := strings.Index(args, "master process (")
	if i < 0 {
		return ""
	}
	tail := args[i+len("master process ("):]
	j := strings.IndexByte(tail, ')')
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(tail[:j])
}

// guessConfigPath tries common locations when cmdline didn't carry it.
// Falls back to readlink of the master's exe → fpm root → conf.
func guessConfigPath(pid int) string {
	exe, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if exe == "" {
		return ""
	}
	// /usr/sbin/php-fpm8.3 → try /etc/php/8.3/fpm/php-fpm.conf
	if strings.Contains(exe, "php-fpm") {
		// extract trailing version digits
		base := filepath.Base(exe)
		for _, cand := range candidatesFor(base) {
			if fileExists(cand) {
				return cand
			}
		}
	}
	return ""
}

func candidatesFor(base string) []string {
	// php-fpm8.3 → 8.3 ; php-fpm83 → 83 ; php-fpm → ""
	verDot := ""
	verRaw := ""
	for i := len(base) - 1; i >= 0; i-- {
		c := base[i]
		if (c >= '0' && c <= '9') || c == '.' {
			verDot = string(c) + verDot
		} else {
			break
		}
	}
	verRaw = strings.ReplaceAll(verDot, ".", "")
	out := []string{
		"/etc/php-fpm.conf",
		"/etc/php-fpm.d/www.conf",
	}
	if verDot != "" {
		out = append(out,
			"/etc/php/"+verDot+"/fpm/php-fpm.conf",
			"/www/server/php/"+verRaw+"/etc/php-fpm.conf",
			"/usr/local/php"+verRaw+"/etc/php-fpm.conf",
		)
	}
	return out
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// phpVersionFromPath extracts a "8.3"-style version from a config path
// like /www/server/php/83/etc/php-fpm.conf or /etc/php/8.3/fpm/...
func phpVersionFromPath(p string) string {
	if p == "" {
		return ""
	}
	// Try /etc/php/8.3/fpm/...
	parts := strings.Split(p, string(os.PathSeparator))
	for i, part := range parts {
		if part == "php" && i+1 < len(parts) {
			next := parts[i+1]
			if isVersionLike(next) {
				return next
			}
		}
	}
	// Try /www/server/php/83/... or /usr/local/php83/...
	for _, part := range parts {
		if strings.HasPrefix(part, "php") {
			suf := strings.TrimPrefix(part, "php")
			if len(suf) == 2 && allDigits(suf) {
				return suf[:1] + "." + suf[1:]
			}
			if len(suf) == 3 && suf[1] == '.' {
				return suf
			}
		}
		if len(part) == 2 && allDigits(part) {
			// /www/server/php/83/etc/php-fpm.conf — bare "83" directory
			return part[:1] + "." + part[1:]
		}
	}
	return ""
}

func isVersionLike(s string) bool {
	dot := false
	for _, c := range s {
		if c == '.' {
			dot = true
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return dot
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// parseFPMConfig walks an FPM config file looking for the directives we
// care about: `listen`, `pm.status_path`, and `[pool-name]`.
// PHP-FPM configs use ini-style with possible includes; we don't follow
// includes here — mergePoolConfigs handles the pool.d/ sibling case.
func parseFPMConfig(path string, d *discovered) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if name != "global" && name != "" {
				d.poolName = name
			}
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "listen":
			d.listenAddr = v
		case "pm.status_path":
			d.statusPath = v
		}
	}
}

// mergePoolConfigs reads any *.conf in the pool.d/ sibling of the main
// config (Debian/Ubuntu convention) or php-fpm.d/ (aaPanel) and merges
// directives. Pool-level listen/status_path override global.
func mergePoolConfigs(mainPath string, d *discovered) {
	if mainPath == "" {
		return
	}
	dir := filepath.Dir(mainPath)
	for _, sub := range []string{"pool.d", "php-fpm.d"} {
		entries, _ := os.ReadDir(filepath.Join(dir, sub))
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			parseFPMConfig(filepath.Join(dir, sub, e.Name()), d)
		}
	}
}

func splitKV(s string) (k, v string, ok bool) {
	// strip inline comments
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	eq := strings.IndexByte(s, '=')
	if eq < 0 {
		return "", "", false
	}
	k = strings.TrimSpace(s[:eq])
	v = strings.TrimSpace(s[eq+1:])
	// strip surrounding quotes
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return k, v, true
}

// findWorkers returns all worker PIDs whose PPid == masterPID.
func findWorkers(masterPID int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pid == masterPID {
			continue
		}
		if readPPid(pid) == masterPID {
			out = append(out, pid)
		}
	}
	return out
}

// readPPid reads PPid from /proc/<pid>/status.
func readPPid(pid int) int {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PPid:") {
			ppid, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			return ppid
		}
	}
	return 0
}
