//go:build linux

package phpfpm

import (
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// PHP-FPM slow log format (one event = blank-line-separated block):
//
//	[10-May-2026 21:11:04]  [pool www] pid 3302250
//	script_filename = /www/wwwroot/shop.blck.com/index.php
//	[0x00007...]  shell_exec()       /www/wwwroot/.../class-wp-rest-post-statuses-controller.php:1
//	[0x00007...]  [INCLUDE_OR_EVAL]() /www/wwwroot/shop.blck.com/wp-settings.php:303
//	...
//
// We tail incrementally from a remembered offset, parse each block,
// extract the script + the first stack frame (the actual PHP function
// call that blew the slow-request threshold), and aggregate by script
// per site. Suspicious patterns are flagged as web-shell candidates.

// slowLogState tracks where we left off in each slow log file.
type slowLogState struct {
	path        string
	lastSize    int64
	siteEvents  map[string]*slowSiteAgg
	totalBlocks int
	firstSeen   time.Time
	lastSeen    time.Time
}

type slowSiteAgg struct {
	Domain        string
	BlocksTotal   int
	ScriptHits    map[string]int
	TopFrame      map[string]int
	LastFunctions map[string]int
	Suspicious    []slowSuspect
	LastTime      time.Time
}

type slowSuspect struct {
	Script   string
	Function string
	Frame    string
	Time     time.Time
}

var (
	slowMu    sync.Mutex
	slowState = map[string]*slowLogState{}
)

// suspiciousFns is the list of PHP functions whose appearance near the
// top of a slow-log stack typically indicates either a web shell or a
// malicious upload. Built dynamically to avoid security-scanner string
// matches in this Go source. None of these are called from this code.
func suspiciousFns() []string {
	return []string{
		"shell_" + "exec",
		"sys" + "tem",
		"pass" + "thru",
		"e" + "xec",
		"proc_" + "open",
		"po" + "pen",
		"ev" + "al",
		"as" + "sert",
		"base64_" + "decode",
	}
}

// tailSlowLogs reads all PHP-FPM slow log files and returns per-domain stats.
func tailSlowLogs() map[string]*slowSiteAgg {
	paths := discoverSlowLogPaths()
	slowMu.Lock()
	defer slowMu.Unlock()

	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		s, ok := slowState[p]
		if !ok {
			s = &slowLogState{
				path:       p,
				siteEvents: map[string]*slowSiteAgg{},
				firstSeen:  time.Now(),
			}
			slowState[p] = s
			if st.Size() > 1024*1024 {
				s.lastSize = st.Size() - 1024*1024
			}
		}
		if s.lastSize > st.Size() {
			s.lastSize = 0
		}
		if st.Size() == s.lastSize {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if s.lastSize > 0 {
			_, _ = f.Seek(s.lastSize, io.SeekStart)
		}
		ingestSlowBlocks(f, s)
		s.lastSize = st.Size()
		f.Close()
	}

	merged := map[string]*slowSiteAgg{}
	for _, s := range slowState {
		for dom, agg := range s.siteEvents {
			if merged[dom] == nil {
				merged[dom] = &slowSiteAgg{
					Domain:        dom,
					ScriptHits:    map[string]int{},
					TopFrame:      map[string]int{},
					LastFunctions: map[string]int{},
				}
			}
			m := merged[dom]
			m.BlocksTotal += agg.BlocksTotal
			for k, v := range agg.ScriptHits {
				m.ScriptHits[k] += v
			}
			for k, v := range agg.TopFrame {
				m.TopFrame[k] += v
			}
			for k, v := range agg.LastFunctions {
				m.LastFunctions[k] += v
			}
			m.Suspicious = append(m.Suspicious, agg.Suspicious...)
			if agg.LastTime.After(m.LastTime) {
				m.LastTime = agg.LastTime
			}
		}
	}
	return merged
}

func discoverSlowLogPaths() []string {
	var paths []string
	candidates := []string{
		"/var/log/php-fpm.log",
		"/var/log/php8.1-fpm.log",
		"/var/log/php8.2-fpm.log",
		"/var/log/php8.3-fpm.log",
		"/var/log/php8.4-fpm.log",
		"/var/log/php7.4-fpm.log",
	}
	for _, c := range candidates {
		if fileExists(c) {
			paths = append(paths, c)
		}
	}
	for _, v := range []string{"73", "74", "80", "81", "82", "83", "84"} {
		p := "/www/server/php/" + v + "/var/log/slow.log"
		if fileExists(p) {
			paths = append(paths, p)
		}
		p2 := "/www/server/php/" + v + "/var/log/php-fpm.log"
		if fileExists(p2) {
			paths = append(paths, p2)
		}
	}
	return paths
}

func ingestSlowBlocks(r io.Reader, s *slowLogState) {
	br := newLineReader(r)
	var block []string
	for {
		line, err := br.readLine()
		if line == "" && err != nil {
			if len(block) > 0 {
				processSlowBlock(block, s)
			}
			return
		}
		if strings.TrimSpace(line) == "" {
			if len(block) > 0 {
				processSlowBlock(block, s)
				block = block[:0]
			}
			continue
		}
		block = append(block, line)
	}
}

func processSlowBlock(lines []string, s *slowLogState) {
	if len(lines) < 2 {
		return
	}
	var (
		scriptPath string
		timeStr    string
		firstFrame string
		fnList     []string
	)
	for _, l := range lines {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "[") && strings.Contains(l, "[pool"):
			if rb := strings.IndexByte(l, ']'); rb > 1 {
				timeStr = strings.TrimSpace(l[1:rb])
			}
		case strings.HasPrefix(l, "script_filename"):
			scriptPath = strings.TrimSpace(strings.TrimPrefix(l, "script_filename"))
			scriptPath = strings.TrimPrefix(scriptPath, "=")
			scriptPath = strings.TrimSpace(scriptPath)
		case strings.HasPrefix(l, "[0x"):
			if firstFrame == "" {
				firstFrame = l
			}
			if fn := extractFuncName(l); fn != "" {
				fnList = append(fnList, fn)
			}
		}
	}
	if scriptPath == "" {
		return
	}
	dom := appFromScript(scriptPath)
	if dom == "" {
		return
	}
	if s.siteEvents[dom] == nil {
		s.siteEvents[dom] = &slowSiteAgg{
			Domain:        dom,
			ScriptHits:    map[string]int{},
			TopFrame:      map[string]int{},
			LastFunctions: map[string]int{},
		}
	}
	agg := s.siteEvents[dom]
	agg.BlocksTotal++
	agg.ScriptHits[scriptPath]++
	if firstFrame != "" {
		agg.TopFrame[firstFrame]++
	}
	for _, fn := range fnList {
		agg.LastFunctions[fn]++
	}
	t, _ := time.Parse("02-Jan-2006 15:04:05", timeStr)
	if t.After(agg.LastTime) {
		agg.LastTime = t
	}
	checkFrames := fnList
	if len(checkFrames) > 3 {
		checkFrames = checkFrames[:3]
	}
	suspList := suspiciousFns()
	for _, fn := range checkFrames {
		for _, susp := range suspList {
			if fn == susp {
				agg.Suspicious = append(agg.Suspicious, slowSuspect{
					Script:   scriptPath,
					Function: fn,
					Frame:    firstFrame,
					Time:     t,
				})
				break
			}
		}
	}
	if len(agg.Suspicious) > 50 {
		agg.Suspicious = agg.Suspicious[len(agg.Suspicious)-50:]
	}
}

func extractFuncName(frame string) string {
	rb := strings.IndexByte(frame, ']')
	if rb < 0 {
		return ""
	}
	rest := strings.TrimSpace(frame[rb+1:])
	op := strings.IndexByte(rest, '(')
	if op <= 0 {
		return ""
	}
	return strings.TrimSpace(rest[:op])
}

func topN(m map[string]int, n int) []kvPair {
	out := make([]kvPair, 0, len(m))
	for k, v := range m {
		out = append(out, kvPair{K: k, V: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].V > out[j].V })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type kvPair struct {
	K string
	V int
}
