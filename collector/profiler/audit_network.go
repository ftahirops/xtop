//go:build linux

package profiler

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

func auditNetwork(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	rules := []sysctlRule{
		{
			path: "/proc/sys/net/core/somaxconn",
			name: "net.core.somaxconn",
			description: "Maximum listen backlog queue size",
			impact: "Connection drops under burst traffic",
			weight: 10,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				var need uint64
				switch role {
				case model.RoleWebHosting, model.RoleLoadBalancer:
					need = 65535
				case model.RoleDatabase:
					need = 4096
				default:
					need = 4096
				}
				if v >= need {
					return fmt.Sprintf(">=%d", need), model.RulePass
				}
				if v >= need/2 {
					return fmt.Sprintf("%d", need), model.RuleWarn
				}
				return fmt.Sprintf("%d", need), model.RuleFail
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_max_syn_backlog",
			name: "net.ipv4.tcp_max_syn_backlog",
			description: "Maximum SYN queue length for half-open connections",
			impact: "SYN flood susceptibility, dropped connections",
			weight: 8,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if role == model.RoleWebHosting || role == model.RoleLoadBalancer {
					if v >= 65535 {
						return "65535", model.RulePass
					}
					return "65535", model.RuleFail
				}
				if v >= 4096 {
					return ">=4096", model.RulePass
				}
				return "4096", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_tw_reuse",
			name: "net.ipv4.tcp_tw_reuse",
			description: "Reuse TIME_WAIT sockets for new connections",
			impact: "TIME_WAIT accumulation, ephemeral port exhaustion",
			weight: 8,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				if strings.TrimSpace(cur) == "1" || strings.TrimSpace(cur) == "2" {
					return "1", model.RulePass
				}
				if role == model.RoleLoadBalancer || role == model.RoleWebHosting {
					return "1", model.RuleFail
				}
				return "1", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_fin_timeout",
			name: "net.ipv4.tcp_fin_timeout",
			description: "Seconds to hold FIN_WAIT2 state",
			impact: "Socket leak, memory waste from stale connections",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v <= 15 {
					return "<=15", model.RulePass
				}
				if v <= 30 {
					return "15", model.RuleWarn
				}
				return "15", model.RuleFail
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_keepalive_time",
			name: "net.ipv4.tcp_keepalive_time",
			description: "Seconds before sending keepalive probes",
			impact: "Dead connections held open, resource waste",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v <= 300 {
					return "<=300", model.RulePass
				}
				if v <= 600 {
					return "300", model.RuleWarn
				}
				return "300", model.RuleFail
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_keepalive_intvl",
			name: "net.ipv4.tcp_keepalive_intvl",
			description: "Seconds between keepalive probes",
			impact: "Slow detection of dead connections",
			weight: 3,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v <= 30 {
					return "<=30", model.RulePass
				}
				return "30", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_keepalive_probes",
			name: "net.ipv4.tcp_keepalive_probes",
			description: "Number of keepalive probes before giving up",
			impact: "Too many or too few probes before marking connection dead",
			weight: 3,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v >= 3 && v <= 9 {
					return "3-9", model.RulePass
				}
				return "5", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/net/core/netdev_max_backlog",
			name: "net.core.netdev_max_backlog",
			description: "Maximum packets queued at NIC before processing",
			impact: "Packet drops during traffic bursts",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if role == model.RoleLoadBalancer || role == model.RoleWebHosting {
					if v >= 16384 {
						return ">=16384", model.RulePass
					}
					return "16384", model.RuleFail
				}
				if v >= 5000 {
					return ">=5000", model.RulePass
				}
				return "5000", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_slow_start_after_idle",
			name: "net.ipv4.tcp_slow_start_after_idle",
			description: "Reset congestion window after idle period",
			impact: "Throughput penalty on persistent connections after idle",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				if strings.TrimSpace(cur) == "0" {
					return "0", model.RulePass
				}
				return "0", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/net/ipv4/tcp_mtu_probing",
			name: "net.ipv4.tcp_mtu_probing",
			description: "Enable TCP MTU probing to avoid PMTU black holes",
			impact: "Connection stalls with large packets through broken routers",
			weight: 3,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := strings.TrimSpace(cur)
				if v == "1" || v == "2" {
					return "1", model.RulePass
				}
				return "1", model.RuleWarn
			},
		},
	}

	result := evalSysctlRules(rules, role, model.OptDomainNetwork)

	// Conntrack-specific checks
	if snap.Global.Conntrack.Max > 0 {
		ct := snap.Global.Conntrack
		// Check conntrack max vs current usage
		usePct := float64(ct.Count) / float64(ct.Max) * 100
		rec := "nf_conntrack_max >= 4x current usage"
		status := model.RulePass
		ctFix := ""
		if usePct > 75 {
			status = model.RuleFail
			rec = fmt.Sprintf("%d (current at %.0f%% of max)", ct.Max*4, usePct)
			ctFix = fmt.Sprintf("sysctl -w net.netfilter.nf_conntrack_max=%d && echo 'net.netfilter.nf_conntrack_max=%d' >> /etc/sysctl.d/99-xtop.conf", ct.Max*4, ct.Max*4)
		} else if usePct > 50 {
			status = model.RuleWarn
			rec = fmt.Sprintf("%d (at %.0f%%)", ct.Max*2, usePct)
			ctFix = fmt.Sprintf("sysctl -w net.netfilter.nf_conntrack_max=%d && echo 'net.netfilter.nf_conntrack_max=%d' >> /etc/sysctl.d/99-xtop.conf", ct.Max*2, ct.Max*2)
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainNetwork,
			Name:        "nf_conntrack_max",
			Description: "Connection tracking table capacity",
			Current:     fmt.Sprintf("%d (%.0f%% used)", ct.Max, usePct),
			Recommended: rec,
			Impact:      "New connections silently dropped when table full",
			Fix:         ctFix,
			Status:      status,
			Weight:      8,
		})

		// Check buckets ratio
		if ct.Buckets > 0 {
			ratio := ct.Max / ct.Buckets
			status := model.RulePass
			rec := "max/buckets ratio <= 4"
			bucketFix := ""
			if ratio > 8 {
				status = model.RuleFail
				rec = fmt.Sprintf("Increase buckets to %d", ct.Max/4)
				bucketFix = fmt.Sprintf("echo %d > /sys/module/nf_conntrack/parameters/hashsize", ct.Max/4)
			} else if ratio > 4 {
				status = model.RuleWarn
				rec = fmt.Sprintf("Increase buckets to %d", ct.Max/4)
				bucketFix = fmt.Sprintf("echo %d > /sys/module/nf_conntrack/parameters/hashsize", ct.Max/4)
			}
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainNetwork,
				Name:        "nf_conntrack_buckets",
				Description: "Conntrack hash table bucket count",
				Current:     fmt.Sprintf("%d (ratio %d:1)", ct.Buckets, ratio),
				Recommended: rec,
				Impact:      "Hash collisions causing slow conntrack lookups",
				Fix:         bucketFix,
				Status:      status,
				Weight:      5,
			})
		}
	}

	// NIC-level tuning checks
	for _, iface := range snap.Global.Network {
		name := iface.Name
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "docker") {
			continue
		}

		// Check TX queue length
		txQueuePath := fmt.Sprintf("/sys/class/net/%s/tx_queue_len", name)
		if txStr, err := util.ReadFileString(txQueuePath); err == nil {
			txQ := parseUint(strings.TrimSpace(txStr))
			if txQ < 1000 && (role == model.RoleWebHosting || role == model.RoleLoadBalancer) {
				result = append(result, model.AuditRule{
					Domain:      model.OptDomainNetwork,
					Name:        fmt.Sprintf("nic.txqueuelen[%s]", name),
					Description: fmt.Sprintf("TX queue length for %s", name),
					Current:     fmt.Sprintf("%d", txQ),
					Recommended: ">=1000",
					Impact:      "Packet drops during traffic bursts",
					Fix:         fmt.Sprintf("ip link set %s txqueuelen 10000", name),
					Status:      model.RuleWarn,
					Weight:      3,
				})
			}
		}
	}

	return result
}
