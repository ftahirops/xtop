package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// NetworkCollector reads /proc/net/dev, /proc/net/snmp, and /sys/class/net/.
type NetworkCollector struct{}

func (n *NetworkCollector) Name() string { return "network" }

func (n *NetworkCollector) Collect(snap *model.Snapshot) error {
	if err := n.collectNetDev(snap); err != nil {
		return err
	}
	n.enrichMetadata(snap)
	n.collectSNMP(snap)
	return nil
}

func (n *NetworkCollector) collectNetDev(snap *model.Snapshot) error {
	lines, err := util.ReadFileLines("/proc/net/dev")
	if err != nil {
		return fmt.Errorf("read /proc/net/dev: %w", err)
	}

	var ifaces []model.NetworkStats
	for _, line := range lines {
		if strings.Contains(line, "|") || strings.TrimSpace(line) == "" {
			continue
		}
		ns, ok := parseNetDevLine(line)
		if !ok {
			continue
		}
		if ns.Name == "lo" {
			continue
		}
		ifaces = append(ifaces, ns)
	}
	snap.Global.Network = ifaces
	return nil
}

func parseNetDevLine(line string) (model.NetworkStats, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return model.NetworkStats{}, false
	}
	name := strings.TrimSpace(parts[0])
	fields := strings.Fields(parts[1])
	if len(fields) < 16 {
		return model.NetworkStats{}, false
	}
	return model.NetworkStats{
		Name:      name,
		RxBytes:   util.ParseUint64(fields[0]),
		RxPackets: util.ParseUint64(fields[1]),
		RxErrors:  util.ParseUint64(fields[2]),
		RxDrops:   util.ParseUint64(fields[3]),
		RxFifo:    util.ParseUint64(fields[4]),
		RxFrame:   util.ParseUint64(fields[5]),
		TxBytes:   util.ParseUint64(fields[8]),
		TxPackets: util.ParseUint64(fields[9]),
		TxErrors:  util.ParseUint64(fields[10]),
		TxDrops:   util.ParseUint64(fields[11]),
		TxFifo:    util.ParseUint64(fields[12]),
		TxColls:   util.ParseUint64(fields[13]),
		TxCarrier: util.ParseUint64(fields[14]),
		SpeedMbps: -1, // filled by enrichMetadata
	}, true
}

// enrichMetadata reads /sys/class/net/<iface>/ for each interface to add
// operstate, speed, master (bridge/bond), and interface type classification.
func (n *NetworkCollector) enrichMetadata(snap *model.Snapshot) {
	for i := range snap.Global.Network {
		iface := &snap.Global.Network[i]
		base := "/sys/class/net/" + iface.Name

		// Operstate
		iface.OperState = readSysFile(base + "/operstate")
		if iface.OperState == "" {
			iface.OperState = "unknown"
		}

		// Link speed (only meaningful for up interfaces)
		if s := readSysFile(base + "/speed"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v > 0 {
				iface.SpeedMbps = v
			}
		}

		// Master interface (bridge or bond slave detection)
		if target, err := os.Readlink(base + "/master"); err == nil {
			iface.Master = filepath.Base(target)
		}

		// Interface type classification
		iface.IfType = classifyInterface(iface.Name, base)
	}
}

// classifyInterface determines what kind of network interface this is.
func classifyInterface(name, sysPath string) string {
	// Check for bridge
	if isDir(sysPath + "/bridge") {
		return "bridge"
	}
	// Check for bond master
	if isDir(sysPath + "/bonding") {
		return "bond"
	}
	// Check for VLAN
	if isFile(sysPath + "/../../" + name) {
		// VLAN interfaces have a parent
	}
	// Read uevent or type for more info
	if typeStr := readSysFile(sysPath + "/type"); typeStr != "" {
		if v, err := strconv.Atoi(typeStr); err == nil {
			switch {
			case v == 772:
				return "loopback"
			case v == 776 || v == 778:
				return "tunnel"
			}
		}
	}
	// Name-based heuristics
	switch {
	case strings.HasPrefix(name, "veth"):
		return "veth"
	case strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "br"):
		return "bridge"
	case strings.HasPrefix(name, "bond"):
		return "bond"
	case strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "cni"):
		return "virtual"
	case strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "wg"):
		return "tunnel"
	case strings.Contains(name, "."):
		return "vlan"
	case strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth") ||
		strings.HasPrefix(name, "em") || strings.HasPrefix(name, "p"):
		return "physical"
	case strings.HasPrefix(name, "wl"):
		return "wifi"
	default:
		// Check if it has a device symlink (physical interfaces do)
		if _, err := os.Readlink(sysPath + "/device"); err == nil {
			return "physical"
		}
		return "virtual"
	}
}

func readSysFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (n *NetworkCollector) collectSNMP(snap *model.Snapshot) {
	lines, err := util.ReadFileLines("/proc/net/snmp")
	if err != nil {
		return
	}

	// /proc/net/snmp has pairs of lines: header line then values line
	for i := 0; i+1 < len(lines); i += 2 {
		headers := strings.Fields(lines[i])
		values := strings.Fields(lines[i+1])
		if len(headers) != len(values) || len(headers) < 2 {
			continue
		}

		prefix := headers[0] // "Tcp:", "Udp:", etc.

		switch prefix {
		case "Tcp:":
			for j, h := range headers {
				switch h {
				case "RetransSegs":
					snap.Global.TCP.RetransSegs = util.ParseUint64(values[j])
				case "InSegs":
					snap.Global.TCP.InSegs = util.ParseUint64(values[j])
				case "OutSegs":
					snap.Global.TCP.OutSegs = util.ParseUint64(values[j])
				case "ActiveOpens":
					snap.Global.TCP.ActiveOpens = util.ParseUint64(values[j])
				case "PassiveOpens":
					snap.Global.TCP.PassiveOpens = util.ParseUint64(values[j])
				case "CurrEstab":
					snap.Global.TCP.CurrEstab = util.ParseUint64(values[j])
				case "AttemptFails":
					snap.Global.TCP.AttemptFails = util.ParseUint64(values[j])
				case "EstabResets":
					snap.Global.TCP.EstabResets = util.ParseUint64(values[j])
				case "InErrs":
					snap.Global.TCP.InErrs = util.ParseUint64(values[j])
				case "OutRsts":
					snap.Global.TCP.OutRsts = util.ParseUint64(values[j])
				}
			}
		case "Udp:":
			for j, h := range headers {
				switch h {
				case "InDatagrams":
					snap.Global.UDP.InDatagrams = util.ParseUint64(values[j])
				case "OutDatagrams":
					snap.Global.UDP.OutDatagrams = util.ParseUint64(values[j])
				case "InErrors":
					snap.Global.UDP.InErrors = util.ParseUint64(values[j])
				case "NoPorts":
					snap.Global.UDP.NoPorts = util.ParseUint64(values[j])
				case "RcvbufErrors":
					snap.Global.UDP.RcvbufErrors = util.ParseUint64(values[j])
				case "SndbufErrors":
					snap.Global.UDP.SndbufErrors = util.ParseUint64(values[j])
				}
			}
		}
	}
}
