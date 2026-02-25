package collector

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// cwSocketInfo holds parsed info about a CLOSE_WAIT socket for PID resolution.
type cwSocketInfo struct {
	remoteAddr string    // "ip:port"
	firstSeen  time.Time // when this socket was first observed in CLOSE_WAIT
}

// SocketCollector reads /proc/net/sockstat and /proc/net/tcp for connection states.
type SocketCollector struct {
	portUsersCache    []model.PortUser
	cwLeakersCache    []model.CloseWaitLeaker
	cacheAt           time.Time

	// CLOSE_WAIT age tracking: key = "local_hex->remote_hex", value = first seen time
	cwFirstSeen  map[string]time.Time

	// Growth trend tracking
	cwPrevCount  int
	cwGrowthEWMA float64
}

const socketCacheTTL = 5 * time.Second

func (s *SocketCollector) Name() string { return "socket" }

func (s *SocketCollector) Collect(snap *model.Snapshot) error {
	s.collectSockstat(snap)
	s.collectTCPStates(snap)
	return nil
}

func (s *SocketCollector) collectSockstat(snap *model.Snapshot) {
	lines, err := util.ReadFileLines("/proc/net/sockstat")
	if err != nil {
		return
	}
	ss := &snap.Global.Sockets
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "sockets:":
			ss.SocketsUsed = util.ParseInt(fields[2])
		case "TCP:":
			for i := 1; i+1 < len(fields); i += 2 {
				v := util.ParseInt(fields[i+1])
				switch fields[i] {
				case "inuse":
					ss.TCPInUse = v
				case "orphan":
					ss.TCPOrphan = v
				case "tw":
					ss.TCPTimeWait = v
				case "alloc":
					ss.TCPAlloc = v
				case "mem":
					ss.TCPMem = v
				}
			}
		case "UDP:":
			for i := 1; i+1 < len(fields); i += 2 {
				v := util.ParseInt(fields[i+1])
				switch fields[i] {
				case "inuse":
					ss.UDPInUse = v
				case "mem":
					ss.UDPMem = v
				}
			}
		case "RAW:":
			for i := 1; i+1 < len(fields); i += 2 {
				if fields[i] == "inuse" {
					ss.RawInUse = util.ParseInt(fields[i+1])
				}
			}
		case "FRAG:":
			for i := 1; i+1 < len(fields); i += 2 {
				v := util.ParseInt(fields[i+1])
				switch fields[i] {
				case "inuse":
					ss.FragInUse = v
				case "memory":
					ss.FragMem = v
				}
			}
		}
	}
}

// TCP connection states from /proc/net/tcp
// State values: 01=ESTABLISHED, 02=SYN_SENT, 03=SYN_RECV, 04=FIN_WAIT1,
// 05=FIN_WAIT2, 06=TIME_WAIT, 07=CLOSE, 08=CLOSE_WAIT, 09=LAST_ACK,
// 0A=LISTEN, 0B=CLOSING
func (s *SocketCollector) collectTCPStates(snap *model.Snapshot) {
	st := &snap.Global.TCPStates
	eph := &snap.Global.EphemeralPorts

	// Read ephemeral port range
	eph.RangeLo, eph.RangeHi = readEphemeralRange()

	// Track remote IP stats
	type ipAgg struct {
		established int
		timeWait    int
		closeWait   int
		total       int
	}
	remoteIPs := make(map[string]*ipAgg)

	// Track inodes of ephemeral-port connections for PID resolution
	// inode -> state (only for non-TIME_WAIT ephemeral connections, since TIME_WAIT inode=0)
	ephInodes := make(map[uint64]int)

	// Track CLOSE_WAIT inodes for per-PID attribution
	cwInodes := make(map[uint64]cwSocketInfo)
	cwSeenKeys := make(map[string]bool) // keys seen this tick, for pruning cwFirstSeen

	now := time.Now()
	if s.cwFirstSeen == nil {
		s.cwFirstSeen = make(map[string]time.Time)
	}

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		lines, err := util.ReadFileLines(path)
		if err != nil {
			continue
		}
		for _, line := range lines[1:] { // skip header
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			stateHex := fields[3]
			stateBytes, err := hex.DecodeString(stateHex)
			if err != nil || len(stateBytes) == 0 {
				continue
			}
			state := int(stateBytes[0])

			// Count per-state
			switch state {
			case 0x01:
				st.Established++
			case 0x02:
				st.SynSent++
			case 0x03:
				st.SynRecv++
			case 0x04:
				st.FinWait1++
			case 0x05:
				st.FinWait2++
			case 0x06:
				st.TimeWait++
			case 0x07:
				st.Close++
			case 0x08:
				st.CloseWait++
			case 0x09:
				st.LastAck++
			case 0x0A:
				st.Listen++
			case 0x0B:
				st.Closing++
			}

			// CLOSE_WAIT tracking: build socket key, track first-seen time, collect inode
			if state == 0x08 {
				socketKey := fields[1] + "->" + fields[2]
				cwSeenKeys[socketKey] = true
				if _, ok := s.cwFirstSeen[socketKey]; !ok {
					s.cwFirstSeen[socketKey] = now
				}
				inode := util.ParseUint64(fields[9])
				if inode > 0 {
					cwInodes[inode] = cwSocketInfo{
						remoteAddr: parseFullAddr(fields[2]),
						firstSeen:  s.cwFirstSeen[socketKey],
					}
				}
			}

			// Ephemeral port tracking (local_address is fields[1])
			if eph.RangeHi > 0 {
				localPort := ParseLocalPort(fields[1])
				if localPort >= eph.RangeLo && localPort <= eph.RangeHi {
					eph.InUse++
					switch state {
					case 0x06:
						eph.TimeWaitIn++
					case 0x01:
						eph.EstablishedIn++
					case 0x08:
						eph.CloseWaitIn++
					case 0x02:
						eph.SynSentIn++
					}

					// Collect inode for PID resolution (field 9 is inode)
					inode := util.ParseUint64(fields[9])
					if inode > 0 {
						ephInodes[inode] = state
					}
				}
			}

			// Remote IP tracking (rem_address is fields[2]), skip LISTEN
			if state != 0x0A {
				remIP := parseRemoteIP(fields[2])
				if remIP != "" && remIP != "0.0.0.0" && remIP != "127.0.0.1" {
					agg := remoteIPs[remIP]
					if agg == nil {
						agg = &ipAgg{}
						remoteIPs[remIP] = agg
					}
					agg.total++
					switch state {
					case 0x01:
						agg.established++
					case 0x06:
						agg.timeWait++
					case 0x08:
						agg.closeWait++
					}
				}
			}
		}
	}

	// Prune cwFirstSeen of sockets no longer in CLOSE_WAIT
	for key := range s.cwFirstSeen {
		if !cwSeenKeys[key] {
			delete(s.cwFirstSeen, key)
		}
	}

	// Sort remote IPs by total connections, keep top 10
	type ipEntry struct {
		ip  string
		agg *ipAgg
	}
	var entries []ipEntry
	for ip, agg := range remoteIPs {
		entries = append(entries, ipEntry{ip, agg})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].agg.total > entries[j].agg.total
	})
	if len(entries) > 10 {
		entries = entries[:10]
	}
	for _, e := range entries {
		snap.Global.TopRemoteIPs = append(snap.Global.TopRemoteIPs, model.RemoteIPStats{
			IP:          e.ip,
			Connections: e.agg.total,
			Established: e.agg.established,
			TimeWait:    e.agg.timeWait,
			CloseWait:   e.agg.closeWait,
		})
	}

	// Unified PID resolution: ephemeral port users + CLOSE_WAIT leakers (time-gated)
	if len(ephInodes) > 0 || len(cwInodes) > 0 {
		if time.Since(s.cacheAt) >= socketCacheTTL {
			s.portUsersCache, s.cwLeakersCache = resolveSocketOwners(ephInodes, cwInodes, now)
			s.cacheAt = now
		}
		eph.TopUsers = s.portUsersCache
		snap.Global.CloseWaitLeakers = s.cwLeakersCache
	}

	// CLOSE_WAIT growth EWMA
	delta := st.CloseWait - s.cwPrevCount
	s.cwPrevCount = st.CloseWait
	s.cwGrowthEWMA = 0.3*float64(delta) + 0.7*s.cwGrowthEWMA
	snap.Global.CloseWaitTrend = model.CloseWaitTrend{
		Current:    st.CloseWait,
		GrowthRate: s.cwGrowthEWMA,
		Growing:    s.cwGrowthEWMA > 0.5,
	}
}

// resolveSocketOwners maps socket inodes to PIDs by scanning /proc/*/fd/.
// Resolves both ephemeral port users and CLOSE_WAIT leakers in a single walk.
// Returns (top 10 port users, top 15 CW leakers sorted by count desc).
func resolveSocketOwners(ephInodes map[uint64]int, cwInodes map[uint64]cwSocketInfo, now time.Time) ([]model.PortUser, []model.CloseWaitLeaker) {
	type ephPidAgg struct {
		comm        string
		ports       int
		established int
		closeWait   int
	}
	type cwPidAgg struct {
		comm       string
		count      int
		oldestAge  int
		newestAge  int
		remoteIPs  map[string]bool
	}
	ephPidMap := make(map[int]*ephPidAgg)
	cwPidMap := make(map[int]*cwPidAgg)

	// Build target sets: "socket:[inode]" strings for fast lookup
	// ephLookup: socket string -> state
	// cwLookup: socket string -> cwSocketInfo
	ephLookup := make(map[string]int, len(ephInodes))
	for inode, state := range ephInodes {
		ephLookup[fmt.Sprintf("socket:[%d]", inode)] = state
	}
	cwLookup := make(map[string]cwSocketInfo, len(cwInodes))
	for inode, info := range cwInodes {
		cwLookup[fmt.Sprintf("socket:[%d]", inode)] = info
	}

	totalTargets := len(ephInodes) + len(cwInodes)

	// Scan /proc/*/fd/ — single walk for both ephemeral and CW inodes
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil
	}

	matched := 0

	for _, pe := range procEntries {
		if matched >= totalTargets {
			break
		}
		if !pe.IsDir() {
			continue
		}
		pid := util.ParseInt(pe.Name())
		if pid < 1 {
			continue
		}

		fdDir := filepath.Join("/proc", pe.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		if len(fdEntries) < 3 {
			continue
		}

		var comm string
		for _, fe := range fdEntries {
			target, err := os.Readlink(filepath.Join(fdDir, fe.Name()))
			if err != nil {
				continue
			}

			// Check ephemeral inodes
			if state, ok := ephLookup[target]; ok {
				if comm == "" {
					comm = readCommForPID(pid)
				}
				agg := ephPidMap[pid]
				if agg == nil {
					agg = &ephPidAgg{comm: comm}
					ephPidMap[pid] = agg
				}
				agg.ports++
				switch state {
				case 0x01:
					agg.established++
				case 0x08:
					agg.closeWait++
				}
				matched++
			}

			// Check CW inodes
			if info, ok := cwLookup[target]; ok {
				if comm == "" {
					comm = readCommForPID(pid)
				}
				agg := cwPidMap[pid]
				if agg == nil {
					agg = &cwPidAgg{
						comm:      comm,
						oldestAge: 0,
						newestAge: 999999,
						remoteIPs: make(map[string]bool),
					}
					cwPidMap[pid] = agg
				}
				agg.count++
				ageSec := int(now.Sub(info.firstSeen).Seconds())
				if ageSec > agg.oldestAge {
					agg.oldestAge = ageSec
				}
				if ageSec < agg.newestAge {
					agg.newestAge = ageSec
				}
				if info.remoteAddr != "" && len(agg.remoteIPs) < 3 {
					// Extract just the IP (strip port)
					ip := info.remoteAddr
					if idx := strings.LastIndex(ip, ":"); idx > 0 {
						ip = ip[:idx]
					}
					agg.remoteIPs[ip] = true
				}
				matched++
			}
		}
	}

	// Build ephemeral port users result (top 10)
	type ephEntry struct {
		pid int
		agg *ephPidAgg
	}
	var ephResult []ephEntry
	for pid, agg := range ephPidMap {
		ephResult = append(ephResult, ephEntry{pid, agg})
	}
	sort.Slice(ephResult, func(i, j int) bool {
		return ephResult[i].agg.ports > ephResult[j].agg.ports
	})
	if len(ephResult) > 10 {
		ephResult = ephResult[:10]
	}
	var users []model.PortUser
	for _, r := range ephResult {
		users = append(users, model.PortUser{
			PID:         r.pid,
			Comm:        r.agg.comm,
			Ports:       r.agg.ports,
			Established: r.agg.established,
			CloseWait:   r.agg.closeWait,
		})
	}

	// Build CLOSE_WAIT leakers result (top 15)
	type cwEntry struct {
		pid int
		agg *cwPidAgg
	}
	var cwResult []cwEntry
	for pid, agg := range cwPidMap {
		cwResult = append(cwResult, cwEntry{pid, agg})
	}
	sort.Slice(cwResult, func(i, j int) bool {
		return cwResult[i].agg.count > cwResult[j].agg.count
	})
	if len(cwResult) > 15 {
		cwResult = cwResult[:15]
	}
	var leakers []model.CloseWaitLeaker
	for _, r := range cwResult {
		var remotes []string
		for ip := range r.agg.remoteIPs {
			remotes = append(remotes, ip)
		}
		newest := r.agg.newestAge
		if newest == 999999 {
			newest = 0
		}
		leakers = append(leakers, model.CloseWaitLeaker{
			PID:        r.pid,
			Comm:       r.agg.comm,
			Count:      r.agg.count,
			OldestAge:  r.agg.oldestAge,
			NewestAge:  newest,
			TopRemotes: remotes,
		})
	}

	return users, leakers
}

// readCommForPID reads the process command name from /proc/PID/comm.
func readCommForPID(pid int) string {
	content, err := util.ReadFileString(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(content)
}

// readEphemeralRange reads the ephemeral port range from /proc/sys/net/ipv4/ip_local_port_range.
func readEphemeralRange() (lo, hi int) {
	content, err := util.ReadFileString("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0
	}
	fields := strings.Fields(strings.TrimSpace(content))
	if len(fields) >= 2 {
		lo = util.ParseInt(fields[0])
		hi = util.ParseInt(fields[1])
	}
	return
}

// ParseLocalPort extracts the local port from a /proc/net/tcp local_address field.
func ParseLocalPort(localAddr string) int {
	parts := strings.SplitN(localAddr, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	b, err := hex.DecodeString(parts[1])
	if err != nil || len(b) < 2 {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

// parseFullAddr extracts "ip:port" from a /proc/net/tcp address field (hex encoded).
// Returns empty string on error.
func parseFullAddr(addr string) string {
	ip := parseRemoteIP(addr)
	if ip == "" {
		return ""
	}
	port := ParseLocalPort(addr) // same hex port parsing works for remote too
	return fmt.Sprintf("%s:%d", ip, port)
}

// parseRemoteIP extracts the remote IP from a /proc/net/tcp rem_address field.
// Returns empty string on error.
func parseRemoteIP(remAddr string) string {
	parts := strings.SplitN(remAddr, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	if len(b) == 4 {
		// /proc/net/tcp stores IPv4 in little-endian host order
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	// IPv6 — skip for now (too verbose for top-IP display)
	return ""
}
