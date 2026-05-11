//go:build linux

package phpfpm

import (
	"compress/gzip"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// accessLogState holds the running aggregate for one site's access log.
// We tail by remembered offset — on each tick we read from where we last
// left off so cost is O(new-bytes), not O(file-size).
type accessLogState struct {
	path        string
	lastSize    int64
	lastModTime time.Time

	// Rolling window aggregates (since process start, periodically pruned).
	hits         map[ipURI]int
	statusHits   map[int]int
	totalReqs    int
	totalBytes   int64
	firstSeen    time.Time
	lastSeen     time.Time
}

type ipURI struct {
	IP  string
	URI string // path only (query string stripped)
}

var (
	accLogMu    sync.Mutex
	accLogState = map[string]*accessLogState{} // keyed by file path
)

// tailAccessLogs walks each vhost's access log file, reads new bytes
// since last tick, and updates per-site aggregates. Returns one
// AccessLogSummary per site that had a log we could read.
//
// Cost: ~1 ms per active site (incremental tail). First call per process
// reads up to the last cap-bytes of each log to seed the window.
func tailAccessLogs(vhosts []vhostInfo) map[string]accessLogAgg {
	const seedTailCap = 256 * 1024 // 256 KB on first read per file
	accLogMu.Lock()
	defer accLogMu.Unlock()

	now := time.Now()
	out := map[string]accessLogAgg{}

	for _, v := range vhosts {
		if v.AccessLog == "" {
			continue
		}
		st, err := os.Stat(v.AccessLog)
		if err != nil {
			continue
		}
		s, ok := accLogState[v.AccessLog]
		if !ok {
			s = &accessLogState{
				path:       v.AccessLog,
				hits:       map[ipURI]int{},
				statusHits: map[int]int{},
				firstSeen:  now,
			}
			accLogState[v.AccessLog] = s
			// Seed: read last `seedTailCap` bytes so we have *something*
			// to show on first tick.
			if st.Size() > 0 {
				start := st.Size() - seedTailCap
				if start < 0 {
					start = 0
				}
				s.lastSize = start
			}
		}
		// Log rotated? lastSize > current size means file was truncated.
		if s.lastSize > st.Size() {
			s.lastSize = 0
		}
		newBytes := st.Size() - s.lastSize
		if newBytes <= 0 && s.totalReqs > 0 {
			// No new bytes — emit current aggregate anyway.
			out[v.Domain] = summarize(s, v.Domain)
			continue
		}

		f, err := os.Open(v.AccessLog)
		if err != nil {
			continue
		}
		// gzipped log? Skip (rotated archives — current log is plain).
		if strings.HasSuffix(v.AccessLog, ".gz") {
			f.Close()
			continue
		}
		if s.lastSize > 0 {
			_, _ = f.Seek(s.lastSize, io.SeekStart)
		}
		ingestLines(f, s, now)
		s.lastSize = st.Size()
		s.lastModTime = st.ModTime()
		f.Close()

		out[v.Domain] = summarize(s, v.Domain)
	}

	pruneOldStates(now)
	return out
}

// ingestLines reads one line at a time without bufio.Scanner so we can
// handle very long entries (some apps log huge query strings).
func ingestLines(r io.Reader, s *accessLogState, now time.Time) {
	br := newLineReader(r)
	for {
		line, err := br.readLine()
		if line == "" && err != nil {
			return
		}
		if line == "" {
			continue
		}
		ip, uri, status, bytes, ok := parseAccessLine(line)
		if !ok {
			continue
		}
		// Strip query string for bucketing; we want endpoint cardinality,
		// not unique nonces.
		path := uri
		if q := strings.IndexByte(path, '?'); q >= 0 {
			path = path[:q]
		}
		s.hits[ipURI{IP: ip, URI: path}]++
		s.statusHits[status]++
		s.totalReqs++
		s.totalBytes += int64(bytes)
		s.lastSeen = now
	}
}

// parseAccessLine handles standard nginx/apache combined log format:
//   IP - - [time] "METHOD path HTTP/x" status bytes "referer" "ua"
func parseAccessLine(line string) (ip, uri string, status, bytes int, ok bool) {
	// IP is first field, ends at first space
	sp := strings.IndexByte(line, ' ')
	if sp < 1 {
		return
	}
	ip = line[:sp]
	// Skip until first '"' (start of request)
	q1 := strings.IndexByte(line, '"')
	if q1 < 0 {
		return
	}
	q2 := strings.IndexByte(line[q1+1:], '"')
	if q2 < 0 {
		return
	}
	req := line[q1+1 : q1+1+q2]
	// req = "METHOD path HTTP/x"
	parts := strings.Fields(req)
	if len(parts) >= 2 {
		uri = parts[1]
	} else {
		uri = req
	}
	// status + bytes come right after the closing quote.
	rest := strings.Fields(line[q1+1+q2+1:])
	if len(rest) >= 1 {
		status = atoiSafe(rest[0])
	}
	if len(rest) >= 2 {
		bytes = atoiSafe(rest[1])
	}
	ok = ip != "" && uri != ""
	return
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// accessLogAgg is the per-site rollup we return.
type accessLogAgg struct {
	Domain     string
	TotalReqs  int
	TotalBytes int64
	Status2xx  int
	Status3xx  int
	Status4xx  int
	Status5xx  int
	TopIPs     []ipCount
	TopURIs    []uriCount
	IPURIPairs []ipURIPair // top (ip, uri) combinations — useful for "who's hammering what"
	FirstSeen  time.Time
	LastSeen   time.Time
}

type ipCount struct {
	IP    string
	Hits  int
}
type uriCount struct {
	URI  string
	Hits int
}
type ipURIPair struct {
	IP   string
	URI  string
	Hits int
}

func summarize(s *accessLogState, domain string) accessLogAgg {
	agg := accessLogAgg{
		Domain:     domain,
		TotalReqs:  s.totalReqs,
		TotalBytes: s.totalBytes,
		FirstSeen:  s.firstSeen,
		LastSeen:   s.lastSeen,
	}
	for code, n := range s.statusHits {
		switch {
		case code >= 500:
			agg.Status5xx += n
		case code >= 400:
			agg.Status4xx += n
		case code >= 300:
			agg.Status3xx += n
		case code >= 200:
			agg.Status2xx += n
		}
	}
	ipHits := map[string]int{}
	uriHits := map[string]int{}
	pairs := make([]ipURIPair, 0, len(s.hits))
	for k, n := range s.hits {
		ipHits[k.IP] += n
		uriHits[k.URI] += n
		pairs = append(pairs, ipURIPair{IP: k.IP, URI: k.URI, Hits: n})
	}
	for ip, n := range ipHits {
		agg.TopIPs = append(agg.TopIPs, ipCount{IP: ip, Hits: n})
	}
	for u, n := range uriHits {
		agg.TopURIs = append(agg.TopURIs, uriCount{URI: u, Hits: n})
	}
	sort.Slice(agg.TopIPs, func(i, j int) bool { return agg.TopIPs[i].Hits > agg.TopIPs[j].Hits })
	sort.Slice(agg.TopURIs, func(i, j int) bool { return agg.TopURIs[i].Hits > agg.TopURIs[j].Hits })
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Hits > pairs[j].Hits })
	if len(agg.TopIPs) > 10 {
		agg.TopIPs = agg.TopIPs[:10]
	}
	if len(agg.TopURIs) > 10 {
		agg.TopURIs = agg.TopURIs[:10]
	}
	if len(pairs) > 15 {
		pairs = pairs[:15]
	}
	agg.IPURIPairs = pairs
	return agg
}

// pruneOldStates drops in-memory state for logs we haven't seen activity
// on in 30 minutes. Keeps memory bounded on hosts with many sites.
func pruneOldStates(now time.Time) {
	for k, s := range accLogState {
		if !s.lastSeen.IsZero() && now.Sub(s.lastSeen) > 30*time.Minute {
			delete(accLogState, k)
		}
	}
}

// lineReader reads bytes off an io.Reader and yields one line at a time.
// No fixed buffer cap.
type lineReader struct {
	r   io.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader { return &lineReader{r: r, buf: make([]byte, 0, 4096)} }

func (lr *lineReader) readLine() (string, error) {
	for {
		if i := indexOfByte(lr.buf, '\n'); i >= 0 {
			line := string(lr.buf[:i])
			lr.buf = lr.buf[i+1:]
			return line, nil
		}
		tmp := make([]byte, 4096)
		n, err := lr.r.Read(tmp)
		if n > 0 {
			lr.buf = append(lr.buf, tmp[:n]...)
		}
		if err != nil {
			if len(lr.buf) > 0 {
				out := string(lr.buf)
				lr.buf = nil
				return out, err
			}
			return "", err
		}
	}
}

func indexOfByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// (gzip import retained for future use on rotated logs; silence linter)
var _ = gzip.NewReader
