package collector

import (
	"bufio"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// conntrackCLI caches whether the conntrack CLI is available.
var conntrackCLI string // path to conntrack binary, "" if not found
var conntrackCLIChecked bool

// parseHex64 parses a hex string to uint64, returning 0 on error.
func parseHex64(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return v
}

// SysctlCollector reads conntrack stats and FD usage.
type SysctlCollector struct{}

func (s *SysctlCollector) Name() string { return "sysctl" }

func (s *SysctlCollector) Collect(snap *model.Snapshot) error {
	s.collectConntrack(snap)
	s.collectConntrackTimeouts(snap)
	s.collectConntrackTable(snap)
	s.collectFD(snap)
	return nil
}

func (s *SysctlCollector) collectConntrack(snap *model.Snapshot) {
	ct := &snap.Global.Conntrack
	if v, err := util.ReadFileString("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		ct.Count = util.ParseUint64(strings.TrimSpace(v))
	}
	if v, err := util.ReadFileString("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		ct.Max = util.ParseUint64(strings.TrimSpace(v))
	}
	if v, err := util.ReadFileString("/proc/sys/net/netfilter/nf_conntrack_buckets"); err == nil {
		ct.Buckets = util.ParseUint64(strings.TrimSpace(v))
	}

	// /proc/net/stat/nf_conntrack has additional counters — parse by header keys
	lines, err := util.ReadFileLines("/proc/net/stat/nf_conntrack")
	if err == nil && len(lines) >= 2 {
		s.parseConntrackStatProc(ct, lines)
		return
	}

	// Fallback: conntrack -S (kernel 6.1+ removed /proc/net/stat/nf_conntrack)
	s.parseConntrackStatCLI(ct)
}

// parseConntrackStatProc parses /proc/net/stat/nf_conntrack lines.
func (s *SysctlCollector) parseConntrackStatProc(ct *model.ConntrackStats, lines []string) {
	header := strings.Fields(lines[0])
	colIdx := make(map[string]int, len(header))
	for i, key := range header {
		colIdx[key] = i
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if idx, ok := colIdx["found"]; ok && idx < len(fields) {
			ct.Found += parseHex64(fields[idx])
		}
		if idx, ok := colIdx["invalid"]; ok && idx < len(fields) {
			ct.Invalid += parseHex64(fields[idx])
		}
		if idx, ok := colIdx["insert"]; ok && idx < len(fields) {
			ct.Insert += parseHex64(fields[idx])
		}
		if idx, ok := colIdx["insert_failed"]; ok && idx < len(fields) {
			ct.InsertFailed += parseHex64(fields[idx])
		}
		if idx, ok := colIdx["delete"]; ok && idx < len(fields) {
			ct.Delete += parseHex64(fields[idx])
		}
		if idx, ok := colIdx["drop"]; ok && idx < len(fields) {
			ct.Drop += parseHex64(fields[idx])
		}
		if idx, ok := colIdx["early_drop"]; ok && idx < len(fields) {
			ct.EarlyDrop += parseHex64(fields[idx])
		}
		if idx, ok := colIdx["search_restart"]; ok && idx < len(fields) {
			ct.SearchRestart += parseHex64(fields[idx])
		}
	}
}

// parseConntrackStatCLI runs `conntrack -S` and parses key=value per CPU line.
// Format: cpu=0  found=1071 invalid=889 insert=0 insert_failed=13 drop=13 ...
func (s *SysctlCollector) parseConntrackStatCLI(ct *model.ConntrackStats) {
	bin := findConntrackCLI()
	if bin == "" {
		return
	}

	cmd := exec.Command(bin, "-S")
	cmd.SysProcAttr = nil
	out, err := cmd.Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// Parse key=value pairs on each CPU line
		for _, token := range strings.Fields(line) {
			parts := strings.SplitN(token, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				continue
			}
			switch parts[0] {
			case "found":
				ct.Found += val
			case "invalid":
				ct.Invalid += val
			case "insert":
				ct.Insert += val
			case "insert_failed":
				ct.InsertFailed += val
			case "delete":
				ct.Delete += val
			case "drop":
				ct.Drop += val
			case "early_drop":
				ct.EarlyDrop += val
			case "search_restart":
				ct.SearchRestart += val
			}
		}
	}
}

// findConntrackCLI locates the conntrack binary, caching the result.
func findConntrackCLI() string {
	if conntrackCLIChecked {
		return conntrackCLI
	}
	conntrackCLIChecked = true
	for _, p := range []string{"/usr/sbin/conntrack", "/sbin/conntrack"} {
		if _, err := os.Stat(p); err == nil {
			conntrackCLI = p
			return p
		}
	}
	if p, err := exec.LookPath("conntrack"); err == nil {
		conntrackCLI = p
		return p
	}
	return ""
}

func (s *SysctlCollector) collectConntrackTimeouts(snap *model.Snapshot) {
	t := &snap.Global.ConntrackTimeouts
	base := "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_"
	readTimeout := func(name string) int {
		v, err := util.ReadFileString(base + name)
		if err != nil {
			return 0
		}
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}

	t.Established = readTimeout("established")
	t.TimeWait = readTimeout("time_wait")
	t.Close = readTimeout("close")
	t.CloseWait = readTimeout("close_wait")
	t.SynSent = readTimeout("syn_sent")
	t.SynRecv = readTimeout("syn_recv")
	t.FinWait = readTimeout("fin_wait")
	t.LastAck = readTimeout("last_ack")
	t.Available = t.Established > 0 // at least one readable
}

// conntrackTableCache holds the last parsed conntrack table dissection.
var conntrackTableCache model.ConntrackDissection

// conntrackTableTick counts collection ticks for throttling.
var conntrackTableTick int

// maxConntrackEntries caps the number of entries parsed from nf_conntrack.
const maxConntrackEntries = 50000

func (s *SysctlCollector) collectConntrackTable(snap *model.Snapshot) {
	conntrackTableTick++
	// Parse every 5th tick (~15s at 3s interval)
	if conntrackTableTick%5 != 1 {
		snap.Global.ConntrackDissect = conntrackTableCache
		return
	}

	// Try /proc/net/nf_conntrack first (older kernels)
	if d, ok := s.parseConntrackTableProc(); ok {
		conntrackTableCache = d
		snap.Global.ConntrackDissect = d
		return
	}

	// Fallback: conntrack -L (kernel 6.1+ removed /proc/net/nf_conntrack)
	if d, ok := s.parseConntrackTableCLI(); ok {
		conntrackTableCache = d
		snap.Global.ConntrackDissect = d
		return
	}

	conntrackTableCache.Available = false
	snap.Global.ConntrackDissect = conntrackTableCache
}

// parseConntrackTableProc reads /proc/net/nf_conntrack.
// Format: ipv4  2 tcp  6 431992 ESTABLISHED src=... dst=... sport=... dport=...
func (s *SysctlCollector) parseConntrackTableProc() (model.ConntrackDissection, bool) {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return model.ConntrackDissection{}, false
	}
	defer f.Close()

	return s.parseConntrackLines(bufio.NewScanner(f), true), true
}

// parseConntrackTableCLI runs `conntrack -L` and parses its output.
// Format: tcp  6 431992 ESTABLISHED src=... dst=... sport=... dport=...
// Note: conntrack -L output omits the family prefix (ipv4/ipv6) field.
func (s *SysctlCollector) parseConntrackTableCLI() (model.ConntrackDissection, bool) {
	bin := findConntrackCLI()
	if bin == "" {
		return model.ConntrackDissection{}, false
	}

	cmd := exec.Command(bin, "-L", "-o", "extended")
	cmd.SysProcAttr = nil
	// 5s timeout to avoid blocking if table is huge
	done := make(chan struct{})
	var out []byte
	var cmdErr error
	go func() {
		out, cmdErr = cmd.Output()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		return model.ConntrackDissection{}, false
	}
	if cmdErr != nil {
		return model.ConntrackDissection{}, false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	// -o extended adds family prefix (ipv4/ipv6) like /proc/net/nf_conntrack
	return s.parseConntrackLines(scanner, true), true
}

// parseConntrackLines parses conntrack entries from any source.
// hasFamily=true for /proc/net/nf_conntrack (field[0]=family), false for conntrack -L.
func (s *SysctlCollector) parseConntrackLines(scanner *bufio.Scanner, hasFamily bool) model.ConntrackDissection {
	d := model.ConntrackDissection{
		Available: true,
		CTStates:  make(map[string]int),
	}
	srcCounts := make(map[string]int)
	dstCounts := make(map[string]int)

	// Field offsets differ: proc has family prefix, CLI does not
	protoIdx := 0
	ttlIdx := 2
	stateIdx := 3
	if hasFamily {
		protoIdx = 2
		ttlIdx = 4
		stateIdx = 5
	}

	for scanner.Scan() && d.TotalParsed < maxConntrackEntries {
		line := scanner.Text()
		if strings.HasPrefix(line, "conntrack ") {
			// Skip summary line from conntrack -L ("conntrack v1.x.x ...")
			continue
		}
		fields := strings.Fields(line)
		minFields := ttlIdx + 1
		if len(fields) < minFields {
			continue
		}
		d.TotalParsed++

		proto := strings.ToLower(fields[protoIdx])
		switch proto {
		case "tcp":
			d.TCPCount++
		case "udp":
			d.UDPCount++
		case "icmp":
			d.ICMPCount++
		default:
			d.OtherCount++
		}

		ttl, _ := strconv.Atoi(fields[ttlIdx])
		switch {
		case ttl < 10:
			d.AgeLt10s++
		case ttl < 60:
			d.Age10s60s++
		case ttl < 300:
			d.Age1m5m++
		default:
			d.AgeGt5m++
		}

		if proto == "tcp" && stateIdx < len(fields) && !strings.Contains(fields[stateIdx], "=") {
			d.CTStates[fields[stateIdx]]++
		}

		srcFound, dstFound := false, false
		for _, f := range fields {
			if !srcFound && strings.HasPrefix(f, "src=") {
				srcCounts[strings.TrimPrefix(f, "src=")]++
				srcFound = true
			} else if !dstFound && strings.HasPrefix(f, "dst=") {
				dstCounts[strings.TrimPrefix(f, "dst=")]++
				dstFound = true
			}
			if srcFound && dstFound {
				break
			}
		}
	}

	d.TopSrcIPs = topNIPs(srcCounts, 5)
	d.TopDstIPs = topNIPs(dstCounts, 5)
	return d
}

// topNIPs returns the top N IPs by count from a frequency map.
func topNIPs(counts map[string]int, n int) []model.ConntrackIPCount {
	type kv struct {
		ip    string
		count int
	}
	var pairs []kv
	for ip, c := range counts {
		pairs = append(pairs, kv{ip, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].count > pairs[j].count
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	result := make([]model.ConntrackIPCount, len(pairs))
	for i, p := range pairs {
		result[i] = model.ConntrackIPCount{IP: p.ip, Count: p.count}
	}
	return result
}

func (s *SysctlCollector) collectFD(snap *model.Snapshot) {
	// /proc/sys/fs/file-nr: allocated  free(unused)  max
	content, err := util.ReadFileString("/proc/sys/fs/file-nr")
	if err != nil {
		return
	}
	fields := strings.Fields(content)
	if len(fields) >= 3 {
		snap.Global.FD.Allocated = util.ParseUint64(fields[0])
		snap.Global.FD.Max = util.ParseUint64(fields[2])
	}
}
