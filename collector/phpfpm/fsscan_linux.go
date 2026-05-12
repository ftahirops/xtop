//go:build linux

package phpfpm

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Filesystem scan for suspicious content inside web docroots.
// Two classes of finding:
//   1. Web shells — files containing known PHP shell signatures in head bytes.
//   2. Binaries / odd files — ELF or shebang scripts inside a public docroot.
//
// We cache results for fsCacheTTL so the scan only re-runs every few
// minutes per site.

const (
	fsCacheTTL     = 10 * time.Minute
	fsMaxFilesScan = 2000
	fsReadBytes    = 4096
	fsMaxDepth     = 8
)

var (
	fsScanMu    sync.Mutex
	fsScanCache = map[string]*fsScanResult{}
)

// fsScanSkipOnCold returns true if we should defer scanning this docroot
// because Guardian is active AND there's no cached result yet. Warm
// (cached) results are always served — only the first cold walk is
// expensive enough to warrant skipping under pressure.
func fsScanSkipOnCold(docroot string) bool {
	if !skipDeepProbes.Load() {
		return false
	}
	fsScanMu.Lock()
	defer fsScanMu.Unlock()
	_, cached := fsScanCache[docroot]
	return !cached
}

// invalidateFSCache drops cached scan results for the given site (matched
// by substring against the docroot) or all sites if site == "*".
func invalidateFSCache(site string) {
	fsScanMu.Lock()
	defer fsScanMu.Unlock()
	if site == "*" || site == "" {
		fsScanCache = map[string]*fsScanResult{}
		return
	}
	for k := range fsScanCache {
		if strings.Contains(k, site) {
			delete(fsScanCache, k)
		}
	}
}

type fsScanResult struct {
	scannedAt    time.Time
	filesScanned int
	WebShells    []FSFinding
	Binaries     []FSFinding
}

type FSFinding struct {
	Path     string
	Kind     string
	Signal   string
	Evidence string
	Size     int64
	ModTime  time.Time
}

func scanDocroot(docroot string) ([]FSFinding, []FSFinding) {
	if docroot == "" {
		return nil, nil
	}
	fsScanMu.Lock()
	defer fsScanMu.Unlock()
	if r, ok := fsScanCache[docroot]; ok {
		if time.Since(r.scannedAt) < fsCacheTTL {
			return r.WebShells, r.Binaries
		}
	}
	r := &fsScanResult{scannedAt: time.Now()}
	walkDocroot(docroot, r)
	fsScanCache[docroot] = r
	return r.WebShells, r.Binaries
}

func walkDocroot(docroot string, r *fsScanResult) {
	skipDirs := map[string]bool{
		"vendor":          true,
		"node_modules":    true,
		"cache":           true,
		".git":            true,
		".svn":            true,
		"litespeed-cache": true,
		"phpmyadmin":      true,
		"smarty":          true,
		"twig":            true,
		"composer":        true,
		"vendor-prefixed": true,
		// WordPress / common-framework subtrees that ship Unicode-handling
		// libraries with heavy \x?? escape use. Real shells don't live here.
		"SimplePie":      true,
		"Requests":       true,
		"PHPMailer":      true,
		"IXR":            true,
		"random_compat":  true,
		"sodium_compat":  true,
		"symfony":        true,
		"masterminds":    true,
		"guzzlehttp":     true,
		"psr":            true,
		"react":          true,
	}
	_ = filepath.WalkDir(docroot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if r.filesScanned >= fsMaxFilesScan {
			return filepath.SkipDir
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(docroot, path)
			if depth := strings.Count(rel, string(filepath.Separator)); depth > fsMaxDepth {
				return filepath.SkipDir
			}
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		r.filesScanned++
		ext := strings.ToLower(filepath.Ext(d.Name()))
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		size := fi.Size()

		if oddExt(ext, d.Name()) {
			head, _ := readHead(path, fsReadBytes)
			// Require an additional signal beyond "non-PHP extension":
			// either a shell-pattern or obfuscation match. Bare PHP code
			// inside .tpl/.phar/extensionless framework files is normal
			// (Smarty templates, phpmyadmin internals, wp-cli.phar, etc.).
			if signatureMatchesPHP(head) {
				if reason := matchShellPattern(head); reason != "" {
					r.WebShells = append(r.WebShells, FSFinding{
						Path: path, Kind: "ext-mismatch",
						Signal:   "non-PHP extension + " + reason,
						Evidence: firstNonEmpty(head),
						Size:     size, ModTime: fi.ModTime(),
					})
					return nil
				}
				if reason := matchObfuscated(head, size); reason != "" {
					r.WebShells = append(r.WebShells, FSFinding{
						Path: path, Kind: "ext-mismatch",
						Signal:   "non-PHP extension + " + reason,
						Evidence: firstNonEmpty(head),
						Size:     size, ModTime: fi.ModTime(),
					})
					return nil
				}
			}
			if isELF(head) {
				r.Binaries = append(r.Binaries, FSFinding{
					Path: path, Kind: "elf-binary",
					Signal:   "ELF binary inside webroot",
					Evidence: "ELF magic at file start",
					Size:     size, ModTime: fi.ModTime(),
				})
				return nil
			}
			if hasShebang(head) {
				r.Binaries = append(r.Binaries, FSFinding{
					Path: path, Kind: "shebang-script",
					Signal:   "shell script inside webroot",
					Evidence: firstLine(head),
					Size:     size, ModTime: fi.ModTime(),
				})
				return nil
			}
		}

		if ext == ".php" || ext == ".phtml" || ext == ".phps" || ext == ".pht" || ext == ".php5" || ext == ".php7" {
			head, _ := readHead(path, fsReadBytes)
			// Skip defensive code — file that DECLARES dangerous functions
			// as forbidden/blocked is doing security work, not running it.
			if isDefensiveCode(head, path) {
				return nil
			}
			if reason := matchShellPattern(head); reason != "" {
				r.WebShells = append(r.WebShells, FSFinding{
					Path: path, Kind: "php-shell",
					Signal:   reason,
					Evidence: firstNonEmpty(head),
					Size:     size, ModTime: fi.ModTime(),
				})
			} else if reason := matchObfuscated(head, size); reason != "" {
				r.WebShells = append(r.WebShells, FSFinding{
					Path: path, Kind: "obfuscated",
					Signal:   reason,
					Evidence: firstNonEmpty(head),
					Size:     size, ModTime: fi.ModTime(),
				})
			}
			return nil
		}

		if size >= 4 && size < 50*1024*1024 {
			head, _ := readHead(path, 16)
			if isELF(head) {
				r.Binaries = append(r.Binaries, FSFinding{
					Path: path, Kind: "elf-binary",
					Signal:   "ELF binary inside webroot",
					Evidence: "ELF magic at file start",
					Size:     size, ModTime: fi.ModTime(),
				})
			}
		}
		return nil
	})
	capList(&r.WebShells, 50)
	capList(&r.Binaries, 50)
}

func capList(l *[]FSFinding, n int) {
	if len(*l) > n {
		*l = (*l)[:n]
	}
}

func oddExt(ext, name string) bool {
	// .phar is officially a PHP archive — not suspicious by itself.
	switch ext {
	case ".phtml", ".phps", ".pht", ".php5", ".php7":
		return true
	}
	if ext == ".tkn" || ext == ".bak" || ext == "" {
		return true
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, ".php.") {
		return true
	}
	return false
}

func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	got, _ := f.Read(buf)
	return buf[:got], nil
}

func isELF(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

func hasShebang(b []byte) bool {
	return len(b) >= 2 && b[0] == '#' && b[1] == '!'
}

func signatureMatchesPHP(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "<?php") || strings.Contains(s, "<?=")
}

func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	if len(b) > 80 {
		return string(b[:80])
	}
	return string(b)
}

func firstNonEmpty(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 120 {
		s = s[:120] + ".."
	}
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if c == '\t' || c == '\n' || c == ' ' || (c >= 0x20 && c < 0x7f) {
			out = append(out, c)
		}
	}
	return string(out)
}

// isDefensiveCode returns true if the file looks like a security
// validator / sanitizer that DECLARES dangerous function names as
// a deny-list, rather than calling them. The classic false-positive
// is plugins like "code-snippets/file-validator.php" that contain
// `$forbidden = ['eval', 'shell_exec', 'system', ...]` — flagging
// these would mean every WP security plugin trips the scanner.
//
// Heuristics:
//   - Path component contains "validator", "sanitize", "security"
//   - File content contains `$forbidden`, `$blacklist`, `$denylist`,
//     `$banned_functions`, `$blocked_functions`, or a class name
//     like *Validator/*Sanitizer/*FirewallRule near the top
func isDefensiveCode(head []byte, path string) bool {
	lp := strings.ToLower(path)
	if strings.Contains(lp, "validator") ||
		strings.Contains(lp, "sanitiz") ||
		strings.Contains(lp, "/security/") ||
		strings.Contains(lp, "firewall") {
		return true
	}
	s := string(head)
	if strings.Contains(s, "$forbidden") ||
		strings.Contains(s, "$blacklist") ||
		strings.Contains(s, "$denylist") ||
		strings.Contains(s, "$banned_functions") ||
		strings.Contains(s, "$blocked_functions") ||
		strings.Contains(s, "$dangerous_functions") ||
		strings.Contains(s, "$disabled_functions") {
		return true
	}
	// PHP class name indicating defensive role.
	for _, c := range []string{"class Validator", "class Sanitizer", "class Firewall",
		"class SecurityCheck", "class FunctionBlacklist", "class FunctionDenylist"} {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}

// matchShellPattern returns a human-readable reason if the bytes look
// like a known PHP web-shell pattern. Pattern needles are split across
// string concatenations to avoid this Go source itself tripping naive
// shell-pattern scanners.
func matchShellPattern(b []byte) string {
	s := string(b)
	checks := []struct {
		needle string
		why    string
	}{
		{"ev" + "al($_POST", "code from POST body run as PHP"},
		{"ev" + "al($_GET", "code from URL run as PHP"},
		{"ev" + "al($_REQUEST", "code from request run as PHP"},
		{"ev" + "al(gzinflate", "packed-payload pattern (gzinflate)"},
		{"ev" + "al(base64_" + "decode", "packed-payload pattern (base64)"},
		{"ass" + "ert($_", "assert on user input (equivalent to runtime code-exec)"},
		{"sys" + "tem($_", "system call on user input"},
		{"shell_" + "exec($_", "shell call on user input"},
		{"pass" + "thru($_", "passthru on user input"},
		{"e" + "xec($_", "exec on user input"},
		{"proc_" + "open($_", "proc_open on user input"},
		{"po" + "pen($_", "popen on user input"},
		{"FilesMan", "FilesMan signature (known shell family)"},
		{"WSO " + "Shell", "WSO Shell signature"},
		{"b374k", "b374k signature"},
		{"r57" + "shell", "r57 shell signature"},
		{"c99" + "shell", "c99 shell signature"},
		{"/e\"", "preg_replace /e modifier (legacy code-exec)"},
		{"create_" + "function(", "create_function (legacy code-exec)"},
		{"${\"_\".\"POST\"}", "obfuscated $_POST access"},
		{"${\"_\".\"GET\"}", "obfuscated $_GET access"},
	}
	for _, c := range checks {
		if strings.Contains(s, c.needle) {
			return c.why
		}
	}
	return ""
}

func matchObfuscated(b []byte, size int64) string {
	s := string(b)
	// Packed payload: long base64 blob fed into runtime decode.
	// This needs co-occurrence of "base64_decode" and a long base64
	// run to be confident — both bare blobs (legit cached data) and
	// bare calls (legit data marshalling) are common in normal code.
	if strings.Contains(s, "base64_"+"decode") && size < 100*1024 {
		run := 0
		maxRun := 0
		for _, c := range []byte(s) {
			if isBase64Char(c) {
				run++
				if run > maxRun {
					maxRun = run
				}
			} else {
				run = 0
			}
		}
		if maxRun >= 200 && hasDynamicExec(s) {
			return "long base64 blob + base64_decode + dynamic-exec — likely packed shell"
		}
	}
	// Hex / chr() obfuscation is only suspicious when paired with a
	// runtime code-execution sink. Legitimate Unicode tables (SimplePie,
	// charset libs, mb_* polyfills) routinely contain hundreds of \x??
	// escapes without any exec sink.
	if strings.Count(s, "\\x") > 30 && hasDynamicExec(s) {
		return "many \\x?? hex escapes near a code-exec sink — likely obfuscated shell"
	}
	if strings.Count(s, "chr(") > 20 && hasDynamicExec(s) {
		return "many chr() calls near a code-exec sink — likely obfuscated shell"
	}
	return ""
}

// hasDynamicExec reports whether the bytes contain any of the runtime
// code-execution functions that a packed shell needs to actually run.
// Plain "eval" / "exec" mentions in comments or string lists are ignored
// by requiring an open-paren immediately after — same trick we use for
// matchShellPattern's needles.
func hasDynamicExec(s string) bool {
	for _, n := range []string{
		"e" + "val(",
		"ass" + "ert(",
		"gz" + "inflate(",
		"gz" + "uncompress(",
		"create_" + "function(",
		"prefer" + "encoded(", // some packer-specific helpers
	} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '='
}
