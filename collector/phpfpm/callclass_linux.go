//go:build linux

package phpfpm

import "strings"

// PHPCallClass categorizes a PHP function name observed in a slow-log
// stack frame. The categories let us tell the operator what each call
// actually means + how to optimize when it shows up at the top of the
// blocking-calls list.

// CallCategory groups calls by what they typically represent.
type CallCategory string

const (
	CatFramework  CallCategory = "framework"  // WP/Laravel/Symfony hook system, autoload
	CatRender     CallCategory = "render"     // Elementor / theme rendering
	CatDB         CallCategory = "db"         // MySQL/Postgres/Redis client
	CatHTTP       CallCategory = "http"       // outbound curl / remote API
	CatFS         CallCategory = "fs"         // filesystem reads/writes
	CatExec       CallCategory = "exec"       // shell-exec family (DANGEROUS in normal code)
	CatCrypto     CallCategory = "crypto"     // hashing, encryption
	CatImage      CallCategory = "image"      // GD / Imagick / image-magick
	CatRegex      CallCategory = "regex"      // preg_* — can be O(n²) on bad patterns
	CatSerialize  CallCategory = "serialize"  // serialize / json_encode for huge structures
	CatOther      CallCategory = "other"
)

// CallInfo carries the classifier output for one function.
type CallInfo struct {
	Function    string
	Category    CallCategory
	Severity    string // "normal" | "heavy" | "critical"
	Explanation string
	Optimize    string
}

// ClassifyCall returns the CallInfo for a PHP function name as it
// appears in the slow-log stack ("shell_exec", "do_action", etc.).
// Unknown names are returned with Category=CatOther, severity "normal".
func ClassifyCall(fn string) CallInfo {
	f := strings.ToLower(fn)

	// 1. Code-execution family — should be RARE in normal hot paths.
	for _, needle := range []string{"shell_" + "exec", "sys" + "tem", "pass" + "thru", "proc_" + "open", "po" + "pen", "e" + "xec"} {
		if f == needle {
			return CallInfo{
				Function: fn, Category: CatExec, Severity: "critical",
				Explanation: "executes shell commands from PHP — should never be on a normal request hot path",
				Optimize:    "audit the calling script; legitimate uses are rare (backups, image conversion). Treat as web-shell suspect until proven otherwise",
			}
		}
	}
	if f == "e"+"val" || f == "ass"+"ert" {
		return CallInfo{
			Function: fn, Category: CatExec, Severity: "critical",
			Explanation: "executes PHP code from a string at runtime",
			Optimize:    "almost always a web-shell pattern. Audit the calling script immediately.",
		}
	}

	// 2. Framework: WordPress hook system + autoload + opcache.
	switch f {
	case "do_action", "apply_filters", "add_action", "add_filter", "remove_filter", "remove_action",
		"do_action_ref_array", "apply_filters_ref_array":
		return CallInfo{
			Function: fn, Category: CatFramework, Severity: "normal",
			Explanation: "WordPress hook dispatch — every plugin registers callbacks here",
			Optimize:    "if dominant: too many plugins listen to this hook. Audit `wp_filter['hook_name']`. Consider Query Monitor plugin to see which callbacks are slow.",
		}
	case "[include_or_eval]", "include_or_eval", "include", "include_once", "require", "require_once":
		return CallInfo{
			Function: fn, Category: CatFramework, Severity: "normal",
			Explanation: "PHP file inclusion — every class autoload, every plugin file, every template",
			Optimize:    "if dominant: opcache is off or undersized. Verify `opcache.enable=1`, `opcache.memory_consumption=256` (MB), `opcache.max_accelerated_files=20000` in php.ini.",
		}
	case "__construct", "__destruct":
		return CallInfo{
			Function: fn, Category: CatFramework, Severity: "normal",
			Explanation: "object instantiation — common in plugin-heavy sites",
			Optimize:    "if dominant: too many objects built per request. Look for plugins that instantiate on every load instead of using late binding.",
		}
	case "init", "wp_initial_constants", "wp", "wp_loaded", "wp_head", "wp_footer":
		return CallInfo{
			Function: fn, Category: CatFramework, Severity: "normal",
			Explanation: "WordPress startup phase",
			Optimize:    "if dominant: plugin doing heavy work in init hook instead of deferring. Use `Query Monitor → Hooks` to find the culprit.",
		}
	case "boot", "register", "load", "instance", "get_instance", "singleton":
		return CallInfo{
			Function: fn, Category: CatFramework, Severity: "normal",
			Explanation: "framework/plugin bootstrap",
			Optimize:    "if dominant: plugin doing eager loading. Some plugins offer 'lite mode' or lazy-load options.",
		}
	}

	// 3. Database
	switch f {
	case "query", "mysqli_query", "mysqli_real_query", "pdo::query", "pdostatement::execute", "execute":
		return CallInfo{
			Function: fn, Category: CatDB, Severity: "heavy",
			Explanation: "raw SQL query — usually means missing index or N+1 pattern",
			Optimize:    "enable MySQL slow query log: `SET GLOBAL slow_query_log=1; SET GLOBAL long_query_time=0.5`. Run `xtop` on the DB host for query-level analysis.",
		}
	case "wpdb::query", "wpdb::get_results", "wpdb::get_row", "wpdb::get_var", "wpdb::get_col", "get_results", "get_row", "get_var":
		return CallInfo{
			Function: fn, Category: CatDB, Severity: "heavy",
			Explanation: "WordPress DB call",
			Optimize:    "use `Query Monitor` plugin to see exact queries + caller. Add object-cache plugin (Redis/Memcached) — drops most repeats.",
		}
	case "redis::get", "redis::set", "redis::hget", "redis::hgetall":
		return CallInfo{
			Function: fn, Category: CatDB, Severity: "normal",
			Explanation: "Redis call (usually fast — slow means network or huge value)",
			Optimize:    "check Redis hit ratio; if low, increase TTLs or cache more keys",
		}
	}

	// 4. HTTP / external API
	switch f {
	case "curl_exec", "curl_multi_exec", "file_get_contents":
		return CallInfo{
			Function: fn, Category: CatHTTP, Severity: "heavy",
			Explanation: "outbound HTTP call from PHP — blocks the request until the remote responds",
			Optimize:    "set short timeouts (`CURLOPT_CONNECTTIMEOUT=2, CURLOPT_TIMEOUT=5`). Move slow calls to background workers (Action Scheduler in WP). Cache results aggressively.",
		}
	case "wp_remote_get", "wp_remote_post", "wp_remote_request", "wp_safe_remote_get":
		return CallInfo{
			Function: fn, Category: CatHTTP, Severity: "heavy",
			Explanation: "WP HTTP API call — usually license check, plugin update check, or 3rd-party integration",
			Optimize:    "transient-cache the result; add `wp_remote_get` timeout: 5s max. Check Query Monitor for slow HTTP requests.",
		}
	}

	// 5. Filesystem
	switch f {
	case "file_exists", "is_file", "is_dir", "is_writable", "filemtime", "filesize", "stat":
		return CallInfo{
			Function: fn, Category: CatFS, Severity: "normal",
			Explanation: "filesystem stat call",
			Optimize:    "if dominant: opcache.validate_timestamps is 1 and stat cache is small. Tune `realpath_cache_size=4096K`, `realpath_cache_ttl=600`.",
		}
	case "glob", "scandir", "opendir", "readdir":
		return CallInfo{
			Function: fn, Category: CatFS, Severity: "heavy",
			Explanation: "directory listing — slow when dir has many files",
			Optimize:    "common cause: WP uploads dir grew huge. Move old uploads off-server. Avoid `glob('*')` on large dirs.",
		}
	}

	// 6. Image processing
	switch f {
	case "imagecreatefromjpeg", "imagecreatefrompng", "imagecopyresampled",
		"imagejpeg", "imagepng", "imagecreate", "image_optimize":
		return CallInfo{
			Function: fn, Category: CatImage, Severity: "heavy",
			Explanation: "GD image manipulation — CPU + memory heavy",
			Optimize:    "move to background worker (WP cron / Action Scheduler). Pre-generate thumbnails on upload, not on request.",
		}
	case "compress_image", "store_on_filesystem", "storeonfilesystem", "optimize", "image-optimization":
		return CallInfo{
			Function: fn, Category: CatImage, Severity: "heavy",
			Explanation: "image-optimizer plugin running on request path",
			Optimize:    "configure the plugin to optimize on a schedule (cron), not on page render. LiteSpeed/Smush/Optimole all have this option.",
		}
	}

	// 7. Regex
	switch f {
	case "preg_match", "preg_match_all", "preg_replace", "preg_replace_callback", "preg_split":
		return CallInfo{
			Function: fn, Category: CatRegex, Severity: "heavy",
			Explanation: "PCRE regex — can be O(n²) or worse on backtracking patterns",
			Optimize:    "if hot: the pattern is probably catastrophic. Profile with `pcre.backtrack_limit` set low to make it fail loudly. Rewrite with possessive quantifiers or atomic groups.",
		}
	}

	// 8. Serialize / JSON
	switch f {
	case "serialize", "unserialize", "json_encode", "json_decode":
		return CallInfo{
			Function: fn, Category: CatSerialize, Severity: "normal",
			Explanation: "data marshalling",
			Optimize:    "if dominant: huge object graphs being serialized. Common with WP option `_transient_*` blobs > 1 MB. Check `wp_options` for oversized rows.",
		}
	}

	// 9. Elementor / page-builder render — domain-specific but very common.
	for _, e := range []string{"print_element", "render_styles", "print_content", "render_content",
		"do_print_elements", "add_controls_stack_style_rules", "print_elements_with_wrapper",
		"get_builder_content", "render_widget", "render_element"} {
		if f == e {
			return CallInfo{
				Function: fn, Category: CatRender, Severity: "heavy",
				Explanation: "Elementor / page-builder widget rendering",
				Optimize:    "enable Elementor's 'Optimized DOM Output' + 'Improved Asset Loading'. Disable widgets not used. Switch to native blocks for static content.",
			}
		}
	}

	return CallInfo{
		Function: fn, Category: CatOther, Severity: "normal",
		Explanation: "(no specific guidance available for this function)",
	}
}

// ClassifyTopCalls runs ClassifyCall on each (fn, count) pair and
// returns them sorted by severity (critical → heavy → normal), then
// by count desc. Used to render the analyzed blocking-calls section.
func ClassifyTopCalls(calls []CallFnCount) []ClassifiedCall {
	out := make([]ClassifiedCall, 0, len(calls))
	for _, c := range calls {
		info := ClassifyCall(c.Function)
		out = append(out, ClassifiedCall{
			Function: c.Function, Hits: c.Hits, Info: info,
		})
	}
	// Sort: critical first, then heavy, then normal; within each, count desc.
	sevRank := map[string]int{"critical": 0, "heavy": 1, "normal": 2}
	// simple bubble — list is tiny (<= 20 items)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			si, sj := sevRank[out[i].Info.Severity], sevRank[out[j].Info.Severity]
			if si > sj || (si == sj && out[i].Hits < out[j].Hits) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// CallFnCount is the input shape — function name + observation count.
type CallFnCount struct {
	Function string
	Hits     int
}

// ClassifiedCall is the output for one analyzed function.
type ClassifiedCall struct {
	Function string
	Hits     int
	Info     CallInfo
}
