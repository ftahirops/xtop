package collector

import (
	"encoding/hex"
	"fmt"
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
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		lines, err := util.ReadFileLines(path)
		if err != nil {
			continue
		}
		for _, line := range lines[1:] { // skip header
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			stateHex := fields[3]
			stateBytes, err := hex.DecodeString(stateHex)
			if err != nil || len(stateBytes) == 0 {
				continue
			}
			state := int(stateBytes[0])
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
		}
	}
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

func init() {
	// suppress unused import warning
	_ = fmt.Sprintf
}
