package collector

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// SocketCollector reads /proc/net/sockstat and /proc/net/tcp for connection states.
type SocketCollector struct{}

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

	// Resolve top ephemeral port users by PID
	if len(ephInodes) > 0 {
		eph.TopUsers = resolvePortUsers(ephInodes)
	}
}

// resolvePortUsers maps socket inodes to PIDs by scanning /proc/*/fd/.
// Returns top 10 processes by ephemeral port count.
func resolvePortUsers(ephInodes map[uint64]int) []model.PortUser {
	type pidAgg struct {
		comm        string
		ports       int
		established int
		closeWait   int
	}
	pidMap := make(map[int]*pidAgg)

	// Build target set: "socket:[inode]" strings for fast lookup
	inodeStrs := make(map[string]int, len(ephInodes))
	for inode, state := range ephInodes {
		inodeStrs[fmt.Sprintf("socket:[%d]", inode)] = state
	}

	// Scan /proc/*/fd/ — only readlink entries to find socket owners
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	matched := 0
	total := len(ephInodes)

	for _, pe := range procEntries {
		if matched >= total {
			break // all inodes resolved
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

		// Skip processes with very few FDs (unlikely to be port abusers)
		if len(fdEntries) < 3 {
			continue
		}

		var comm string
		for _, fe := range fdEntries {
			target, err := os.Readlink(filepath.Join(fdDir, fe.Name()))
			if err != nil {
				continue
			}
			state, ok := inodeStrs[target]
			if !ok {
				continue
			}
			// Matched — this PID owns this ephemeral port socket
			if comm == "" {
				comm = readCommForPID(pid)
			}
			agg := pidMap[pid]
			if agg == nil {
				agg = &pidAgg{comm: comm}
				pidMap[pid] = agg
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
	}

	// Sort by port count, keep top 10
	type pidEntry struct {
		pid int
		agg *pidAgg
	}
	var result []pidEntry
	for pid, agg := range pidMap {
		result = append(result, pidEntry{pid, agg})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].agg.ports > result[j].agg.ports
	})
	if len(result) > 10 {
		result = result[:10]
	}

	var users []model.PortUser
	for _, r := range result {
		users = append(users, model.PortUser{
			PID:         r.pid,
			Comm:        r.agg.comm,
			Ports:       r.agg.ports,
			Established: r.agg.established,
			CloseWait:   r.agg.closeWait,
		})
	}
	return users
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
