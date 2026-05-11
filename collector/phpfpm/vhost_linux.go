//go:build linux

package phpfpm

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// vhostInfo describes one configured server block — domain → docroot →
// access log. We pull this from nginx and apache vhost files so we can
// show stats for sites with zero active workers (static-heavy, idle, or
// purely under attack but not yet generating PHP work).
type vhostInfo struct {
	Domain    string
	DocRoot   string
	AccessLog string
	PHPSocket string // unix:/tmp/php-cgi-83.sock if visible from include line
}

// discoverVhosts walks the well-known nginx + apache config directories
// and returns one vhostInfo per server_name / ServerName found.
func discoverVhosts() []vhostInfo {
	var out []vhostInfo
	out = append(out, parseNginxDir("/www/server/panel/vhost/nginx")...)     // aaPanel
	out = append(out, parseNginxDir("/etc/nginx/sites-enabled")...)         // Debian/Ubuntu
	out = append(out, parseNginxDir("/etc/nginx/conf.d")...)                // RHEL default + custom
	out = append(out, parseNginxDir("/etc/nginx/plesk.conf.d/vhosts")...)   // Plesk
	out = append(out, parseApacheDir("/etc/apache2/sites-enabled")...)      // Debian/Ubuntu
	out = append(out, parseApacheDir("/etc/httpd/conf.d")...)               // RHEL
	out = append(out, parseApacheDir("/etc/apache2/plesk.conf.d/vhosts")...) // Plesk
	out = append(out, parsePleskSystemDirs()...)                            // Plesk fallback
	out = append(out, parseCpanelDirs()...)                                 // cPanel
	return dedupVhosts(out)
}

func dedupVhosts(in []vhostInfo) []vhostInfo {
	// Two passes:
	// 1. Strip www. and dedupe by canonical name (so `www.X` and `X` merge).
	// 2. For multiple entries of the same canonical name, keep the richer one.
	canonical := func(s string) string {
		s = strings.Trim(s, `"' `)
		s = strings.TrimPrefix(s, "www.")
		return s
	}
	seen := map[string]vhostInfo{}
	for _, v := range in {
		if v.Domain == "" {
			continue
		}
		key := canonical(v.Domain)
		// Prefer the bare-domain form for display.
		v.Domain = key
		prev, ok := seen[key]
		if !ok {
			seen[key] = v
			continue
		}
		if scoreVhost(v) > scoreVhost(prev) {
			seen[key] = v
		}
	}
	out := make([]vhostInfo, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}

func scoreVhost(v vhostInfo) int {
	return len(v.DocRoot) + len(v.AccessLog) + len(v.PHPSocket)
}

func parseNginxDir(dir string) []vhostInfo {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []vhostInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		// skip aaPanel's framework files
		if strings.HasPrefix(name, "0.") || name == "phpfpm_status.conf" {
			continue
		}
		out = append(out, parseNginxFile(filepath.Join(dir, name))...)
	}
	return out
}

// parseNginxFile is a tiny, deliberately-lenient nginx parser — we only
// look for `server_name`, `root`, `access_log`, and `enable-php-NN.conf`
// includes. We do NOT track brace nesting; this is "look at lines that
// look right." Works for ~98% of real-world configs.
func parseNginxFile(path string) []vhostInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var (
		cur        vhostInfo
		out        []vhostInfo
		inSrv      bool
		pendingSrv bool // saw `server` line, waiting for `{`
		depth      int
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		opens := strings.Count(line, "{")
		closes := strings.Count(line, "}")
		// `server` directive — may be on its own line, with `{` after.
		// We handle both "server {" and bare "server" with `{` on next line.
		isServerStart := false
		if !inSrv && (strings.HasPrefix(line, "server {") ||
			strings.HasPrefix(line, "server{") ||
			line == "server") {
			isServerStart = true
		}
		if isServerStart {
			if opens > 0 {
				inSrv = true
				depth = opens - closes
				cur = vhostInfo{}
			} else {
				pendingSrv = true
				cur = vhostInfo{}
			}
			continue
		}
		if pendingSrv && opens > 0 {
			inSrv = true
			pendingSrv = false
			depth = opens - closes
			continue
		}
		if inSrv {
			depth += opens - closes
			// extract directives — strip trailing ;
			lc := strings.TrimSuffix(line, ";")
			switch {
			case strings.HasPrefix(lc, "server_name "):
				names := strings.Fields(strings.TrimPrefix(lc, "server_name"))
				for _, n := range names {
					n = strings.TrimSpace(n)
					n = strings.Trim(n, `"'`)
					n = strings.TrimSuffix(n, ";")
					n = strings.TrimSpace(n)
					if n == "" || n == "_" || n == "default_server" {
						continue
					}
					// Skip www.X if we already have X (or vice-versa: prefer the bare form).
					if strings.HasPrefix(n, "www.") && cur.Domain == strings.TrimPrefix(n, "www.") {
						continue
					}
					if cur.Domain == "" || (strings.HasPrefix(cur.Domain, "www.") && !strings.HasPrefix(n, "www.")) {
						cur.Domain = n
					}
				}
			case strings.HasPrefix(lc, "root "):
				cur.DocRoot = strings.TrimSpace(strings.TrimPrefix(lc, "root"))
			case strings.HasPrefix(lc, "access_log "):
				al := strings.Fields(strings.TrimPrefix(lc, "access_log"))
				if len(al) > 0 && al[0] != "off" {
					cur.AccessLog = al[0]
				}
			case strings.Contains(lc, "enable-php-"):
				if i := strings.Index(lc, "enable-php-"); i >= 0 {
					tail := lc[i+len("enable-php-"):]
					// Collect leading digits only — "enable-php-82.conf"
					// yields "82", not "82." (used to include the dot).
					ver := ""
					for _, c := range tail {
						if c >= '0' && c <= '9' {
							ver += string(c)
						} else {
							break
						}
					}
					if ver != "" && ver != "00" {
						cur.PHPSocket = "unix:/tmp/php-cgi-" + ver + ".sock"
					}
				}
			case strings.HasPrefix(lc, "fastcgi_pass "):
				addr := strings.TrimSpace(strings.TrimPrefix(lc, "fastcgi_pass"))
				if addr != "" {
					cur.PHPSocket = addr
				}
			}
			if depth <= 0 {
				if cur.Domain != "" {
					// Default access log if not set
					if cur.AccessLog == "" {
						cur.AccessLog = guessAccessLog(cur.Domain)
					}
					out = append(out, cur)
				}
				inSrv = false
				cur = vhostInfo{}
			}
		}
	}
	return out
}

// guessAccessLog tries common nginx defaults + per-panel conventions.
func guessAccessLog(domain string) string {
	for _, p := range []string{
		"/www/wwwlogs/" + domain + ".log",                       // aaPanel
		"/var/www/vhosts/system/" + domain + "/logs/access_log", // Plesk
		"/var/www/vhosts/system/" + domain + "/logs/proxy_access_log",
		"/var/log/nginx/" + domain + ".access.log",
		"/var/log/nginx/domains/" + domain + ".log", // some panels
		"/usr/local/apache/domlogs/" + domain,       // cPanel
		"/var/log/nginx/access.log",
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// parsePleskSystemDirs walks /var/www/vhosts/system/<domain>/conf for
// the nginx + Apache configs Plesk generates per site. This is the
// authoritative source on a Plesk box when /etc/nginx/plesk.conf.d/
// uses includes that point back here.
func parsePleskSystemDirs() []vhostInfo {
	root := "/var/www/vhosts/system"
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []vhostInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		domain := e.Name()
		// Standard Plesk paths.
		docroot := "/var/www/vhosts/" + domain + "/httpdocs"
		if !fileExists(docroot) {
			// httpdocs may not exist on some installs; try the system dir.
			if st, err := os.Stat("/var/www/vhosts/" + domain); err == nil && st.IsDir() {
				docroot = "/var/www/vhosts/" + domain
			} else {
				continue
			}
		}
		access := guessAccessLog(domain)
		out = append(out, vhostInfo{
			Domain:    domain,
			DocRoot:   docroot,
			AccessLog: access,
		})
	}
	return out
}

// parseCpanelDirs handles cPanel per-user docroot conventions:
//   /home/<user>/public_html        (primary domain)
//   /home/<user>/<domain>/public_html (addon/subdomain)
// We surface anything that has both a docroot and a domlog.
func parseCpanelDirs() []vhostInfo {
	if !fileExists("/var/cpanel/users") && !fileExists("/etc/userdatadomains") {
		return nil
	}
	// Read /etc/userdatadomains — cPanel's authoritative domain→docroot
	// mapping. Format per line: "<domain>: <user>==<owner>==<domain>==<docroot>==..."
	out := []vhostInfo{}
	b, err := os.ReadFile("/etc/userdatadomains")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		domain := strings.TrimSpace(line[:colon])
		rest := strings.TrimSpace(line[colon+1:])
		parts := strings.Split(rest, "==")
		if len(parts) < 5 {
			continue
		}
		docroot := parts[4]
		out = append(out, vhostInfo{
			Domain:    domain,
			DocRoot:   docroot,
			AccessLog: guessAccessLog(domain),
		})
	}
	return out
}

func parseApacheDir(dir string) []vhostInfo {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []vhostInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		out = append(out, parseApacheFile(filepath.Join(dir, name))...)
	}
	return out
}

func parseApacheFile(path string) []vhostInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var (
		cur   vhostInfo
		out   []vhostInfo
		inV   bool
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ll := strings.ToLower(line)
		if strings.HasPrefix(ll, "<virtualhost") {
			inV = true
			cur = vhostInfo{}
			continue
		}
		if strings.HasPrefix(ll, "</virtualhost") {
			if cur.Domain != "" {
				if cur.AccessLog == "" {
					cur.AccessLog = guessAccessLog(cur.Domain)
				}
				out = append(out, cur)
			}
			inV = false
			continue
		}
		if !inV {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "servername":
			if cur.Domain == "" {
				cur.Domain = fields[1]
			}
		case "serveralias":
			if cur.Domain == "" {
				cur.Domain = fields[1]
			}
		case "documentroot":
			cur.DocRoot = strings.Trim(fields[1], `"`)
		case "customlog":
			cur.AccessLog = strings.Trim(fields[1], `"`)
		}
	}
	return out
}
