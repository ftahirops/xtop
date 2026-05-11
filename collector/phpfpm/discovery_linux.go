//go:build linux

// Package phpfpm produces a per-pool view of every running php-fpm master.
//
// Generic, layout-agnostic discovery:
//   - one master can have MANY pools (Plesk, cPanel: per-site pools)
//   - one master can have ONE pool (aaPanel, Debian default: single `[www]`)
//   - listen sockets may be absolute, relative, unix:, or host:port
//   - each pool may declare its own pm.status_path
//
// We discover masters via /proc, parse their config + every conf file in
// `pool.d/`, `php-fpm.d/`, and any `include=` glob the master references.
// For each pool we resolve `listen=` to an absolute address by trying
// (in order): Plesk convention → chdir-relative → common /run paths.

package phpfpm

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// discoveredMaster is one running php-fpm master process and the pools
// it serves. A master may host many pools (Plesk: one per site) or one
// (aaPanel, vanilla Debian).
type discoveredMaster struct {
	pid        int
	configPath string
	phpVersion string
	pools      []discoveredPool
}

// discoveredPool is one named pool inside a master.
type discoveredPool struct {
	name       string // e.g. "www" or "safedriveruae.com"
	listen     string // resolved address — absolute path, host:port, etc.
	rawListen  string // original (un-resolved) directive value, for debug
	statusPath string // pm.status_path if set on this pool
	chdir      string
	user       string
	group      string
	// Pool config file we parsed it from — useful for debug.
	configFile string
}

// discoverMasters walks /proc for php-fpm masters and parses each one's
// full pool list.
func discoverMasters() []discoveredMaster {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []discoveredMaster
	for _, e := range procEntries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm := readComm(pid)
		if !isFPMComm(comm) {
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
		dm := discoveredMaster{
			pid:        pid,
			configPath: cfgPath,
			phpVersion: phpVersionFromPath(cfgPath),
		}
		dm.pools = collectPools(cfgPath)
		out = append(out, dm)
	}
	return out
}

func isFPMComm(c string) bool {
	if c == "" {
		return false
	}
	if c == "php-fpm" || strings.HasPrefix(c, "php-fpm") {
		return true
	}
	// Some distros truncate comm to 15 chars: "php-fpm8.3"
	return false
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
func readCmdline(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// extractConfigPath pulls the config path from "master process (/path/to/php-fpm.conf)".
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

// guessConfigPath tries common config locations when cmdline lost it.
func guessConfigPath(pid int) string {
	exe, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if exe == "" {
		return ""
	}
	if !strings.Contains(exe, "php-fpm") {
		return ""
	}
	base := filepath.Base(exe)
	for _, cand := range candidatesFor(base) {
		if fileExists(cand) {
			return cand
		}
	}
	return ""
}

func candidatesFor(base string) []string {
	verDot := ""
	for i := len(base) - 1; i >= 0; i-- {
		c := base[i]
		if (c >= '0' && c <= '9') || c == '.' {
			verDot = string(c) + verDot
		} else {
			break
		}
	}
	verRaw := strings.ReplaceAll(verDot, ".", "")
	out := []string{
		"/etc/php-fpm.conf",
		"/etc/php-fpm.d/www.conf",
	}
	if verDot != "" {
		out = append(out,
			"/etc/php/"+verDot+"/fpm/php-fpm.conf",
			"/www/server/php/"+verRaw+"/etc/php-fpm.conf",
			"/usr/local/php"+verRaw+"/etc/php-fpm.conf",
			"/opt/plesk/php/"+verDot+"/etc/php-fpm.conf",
			"/opt/cpanel/ea-php"+verRaw+"/root/etc/php-fpm.conf",
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

// phpVersionFromPath extracts "8.3" from a config path.
func phpVersionFromPath(p string) string {
	if p == "" {
		return ""
	}
	parts := strings.Split(p, string(os.PathSeparator))
	for i, part := range parts {
		if (part == "php" || strings.HasPrefix(part, "ea-php")) && i+1 < len(parts) {
			next := parts[i+1]
			if isVersionLike(next) {
				return next
			}
			suf := strings.TrimPrefix(part, "ea-php")
			if len(suf) == 2 && allDigits(suf) {
				return suf[:1] + "." + suf[1:]
			}
		}
	}
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

// collectPools returns every pool the master serves. It:
//   1. parses the main config for `include = ...` globs
//   2. parses each glob-matched file as a pool config
//   3. also scans pool.d/ and php-fpm.d/ siblings of the main config
//      (Debian/Ubuntu/aaPanel convention)
//
// Each `[section]` defines a pool. Directives before any section are
// considered global and ignored for pool building (but `include` is
// honored).
func collectPools(mainPath string) []discoveredPool {
	if mainPath == "" {
		return nil
	}
	// Files we'll parse: main + everything its includes point to +
	// pool.d / php-fpm.d siblings.
	files := []string{mainPath}
	files = append(files, gatherIncludes(mainPath)...)
	files = append(files, gatherSiblingPoolDirs(mainPath)...)

	seen := map[string]bool{}
	var pools []discoveredPool
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		pools = append(pools, parsePoolsFromFile(f)...)
	}

	// Deduplicate pools by name (LATER definition wins — same as PHP-FPM).
	byName := map[string]int{}
	uniq := pools[:0]
	for _, p := range pools {
		if i, ok := byName[p.name]; ok {
			uniq[i] = p
			continue
		}
		byName[p.name] = len(uniq)
		uniq = append(uniq, p)
	}
	return uniq
}

func gatherIncludes(mainPath string) []string {
	f, err := os.Open(mainPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments.
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if !strings.HasPrefix(line, "include") {
			continue
		}
		// include = /path/*.conf
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		pat := strings.TrimSpace(line[eq+1:])
		// Make relative include paths absolute against config dir.
		if !filepath.IsAbs(pat) {
			pat = filepath.Join(filepath.Dir(mainPath), pat)
		}
		matches, _ := filepath.Glob(pat)
		out = append(out, matches...)
	}
	return out
}

func gatherSiblingPoolDirs(mainPath string) []string {
	dir := filepath.Dir(mainPath)
	var out []string
	for _, sub := range []string{"pool.d", "php-fpm.d"} {
		entries, _ := os.ReadDir(filepath.Join(dir, sub))
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			out = append(out, filepath.Join(dir, sub, e.Name()))
		}
	}
	return out
}

// parsePoolsFromFile scans one ini file and returns every `[name]` pool.
// Lines outside any section are ignored (this file is invoked for both
// the main config and pool config files; the main config's only
// interesting content for us is the include directive, handled separately).
func parsePoolsFromFile(path string) []discoveredPool {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var pools []discoveredPool
	var cur *discoveredPool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if name == "" || name == "global" {
				cur = nil
				continue
			}
			pools = append(pools, discoveredPool{name: name, configFile: path})
			cur = &pools[len(pools)-1]
			continue
		}
		if cur == nil {
			continue // pre-section directive (e.g. main config's [global])
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "listen":
			cur.rawListen = v
		case "pm.status_path":
			cur.statusPath = v
		case "chdir":
			cur.chdir = v
		case "user":
			cur.user = v
		case "group":
			cur.group = v
		}
	}
	// Resolve listen for each pool we just parsed in this file.
	for i := range pools {
		pools[i].listen = resolveListen(&pools[i])
	}
	return pools
}

// resolveListen returns the address we should dial. PHP-FPM lets `listen`
// be one of: absolute /path/sock, unix:/path/sock, host:port, :port,
// port alone, or — most awkward — a relative socket name that the
// operator's framework (Plesk) resolves at runtime via a per-pool
// `prefix` or umask hack.
//
// Strategy when value is relative:
//   1. Plesk convention: /var/www/vhosts/system/<pool_name>/<listen>
//   2. <chdir>/<listen> if chdir is set and non-/
//   3. /run/<listen>
//   4. /var/run/<listen>
//   5. /tmp/<listen>
//
// First path that actually exists wins. If none exist we still return
// the best guess so the operator sees a meaningful error.
func resolveListen(p *discoveredPool) string {
	v := strings.TrimSpace(p.rawListen)
	if v == "" {
		return ""
	}
	// unix:/path → unwrap.
	if strings.HasPrefix(v, "unix:") {
		v = strings.TrimPrefix(v, "unix:")
	}
	// Absolute path → use as-is.
	if strings.HasPrefix(v, "/") {
		return v
	}
	// TCP variants → use as-is.
	if strings.Contains(v, ":") {
		return v
	}
	// Bare port number → assume TCP localhost.
	if allDigits(v) {
		return "127.0.0.1:" + v
	}
	// Relative socket name. Try fallbacks.
	candidates := []string{
		"/var/www/vhosts/system/" + p.name + "/" + v, // Plesk
		"/var/www/vhosts/" + p.name + "/" + v,        // older Plesk
	}
	if p.chdir != "" && p.chdir != "/" {
		candidates = append(candidates, filepath.Join(p.chdir, v))
	}
	candidates = append(candidates,
		"/run/"+v,
		"/var/run/"+v,
		"/tmp/"+v,
	)
	for _, c := range candidates {
		if sockExists(c) {
			return c
		}
	}
	// Nothing exists. Return the best-guess Plesk path so the error
	// message is informative.
	return candidates[0]
}

func sockExists(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	// Unix sockets show up as type=socket on Stat; we accept any
	// non-directory inode that exists.
	return !st.IsDir()
}

// findWorkersForPool returns the PIDs of workers attributed to a
// specific pool by parsing each child's `php-fpm: pool <name>` cmdline.
// Generic — works for every layout where workers identify their pool
// (which is the PHP-FPM standard).
func findWorkersForPool(masterPID int, poolName string) []int {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	target := "php-fpm: pool " + poolName
	var out []int
	for _, e := range procEntries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pid == masterPID {
			continue
		}
		if readPPid(pid) != masterPID {
			continue
		}
		args := readCmdline(pid)
		// Match prefix — pool name may be followed by trailing spaces.
		if strings.HasPrefix(args, target) {
			out = append(out, pid)
		}
	}
	return out
}

// findAllWorkersForMaster returns every worker PID under a master,
// regardless of pool. Used as a fallback worker count when pool-name
// matching produces nothing (e.g. on a non-standard build).
func findAllWorkersForMaster(masterPID int) []int {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range procEntries {
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

func splitKV(s string) (k, v string, ok bool) {
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	eq := strings.IndexByte(s, '=')
	if eq < 0 {
		return "", "", false
	}
	k = strings.TrimSpace(s[:eq])
	v = strings.TrimSpace(s[eq+1:])
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return k, v, true
}
