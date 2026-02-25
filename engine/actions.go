package engine

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// SuggestActions generates actionable recommendations using data xtop already has.
// No shell commands — xtop IS the diagnostic tool.
func SuggestActions(result *model.AnalysisResult) []model.Action {
	if result.PrimaryScore < 20 {
		return nil
	}

	var actions []model.Action

	// Find the primary RCA entry
	var primary *model.RCAEntry
	for i := range result.RCA {
		if result.RCA[i].Bottleneck == result.PrimaryBottleneck {
			primary = &result.RCA[i]
			break
		}
	}

	// ── Culprit identification (always first if known) ──
	if result.PrimaryProcess != "" && result.PrimaryPID > 0 {
		actions = append(actions, model.Action{
			Summary: fmt.Sprintf("Top culprit: %s (PID %d) — consuming most %s resources",
				result.PrimaryProcess, result.PrimaryPID, result.PrimaryBottleneck),
		})
	}
	if result.PrimaryCulprit != "" {
		actions = append(actions, model.Action{
			Summary: fmt.Sprintf("Owning cgroup: %s", cleanCgroupName(result.PrimaryCulprit)),
		})
	}

	// ── Point to deep diagnostics for known services ──
	if result.PrimaryProcess != "" {
		if svc := knownService(result.PrimaryProcess); svc != "" {
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Press W for %s deep diagnostics (connections, queries, config) — press O for error rate logs", svc),
			})
		}
	}

	// ── Deployment correlation ──
	if result.RecentDeploy != "" {
		actions = append(actions, model.Action{
			Summary: fmt.Sprintf("Recent deploy detected: %s (PID %d, started %ds ago) — likely trigger",
				result.RecentDeploy, result.RecentDeployPID, result.RecentDeployAge),
		})
	}

	switch result.PrimaryBottleneck {
	case BottleneckCPU:
		actions = append(actions, cpuActions(result, primary)...)
	case BottleneckMemory:
		actions = append(actions, memActions(result, primary)...)
	case BottleneckIO:
		actions = append(actions, ioActions(result, primary)...)
	case BottleneckNetwork:
		actions = append(actions, netActions(result, primary)...)
	}

	// ── Exhaustion predictions (with actual data) ──
	for _, ex := range result.Exhaustions {
		actions = append(actions, exhaustionAction(ex))
	}

	return actions
}

func cpuActions(result *model.AnalysisResult, primary *model.RCAEntry) []model.Action {
	var actions []model.Action

	// Show top CPU owners from xtop's own data
	if len(result.CPUOwners) > 0 {
		var top []string
		for i, o := range result.CPUOwners {
			if i >= 3 {
				break
			}
			if o.PID > 0 {
				top = append(top, fmt.Sprintf("%s(PID %d) %.1f%%", o.Name, o.PID, o.Pct))
			} else {
				top = append(top, fmt.Sprintf("%s %.1f%%", o.Name, o.Pct))
			}
		}
		actions = append(actions, model.Action{
			Summary: fmt.Sprintf("Top CPU consumers: %s", strings.Join(top, ", ")),
		})
	}

	if primary == nil {
		return actions
	}

	for _, c := range primary.Checks {
		if !c.Passed {
			continue
		}
		switch c.Group {
		case "cpu.cgroup.throttle":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Cgroup CPU throttling detected: %s — increase cpu.max quota or reduce load", c.Value),
			})
		case "cpu.steal":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("CPU steal: %s — VM is overcommitted on hypervisor, migrate or resize", c.Value),
			})
		case "cpu.runqueue":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Run queue saturated: %s — more threads than CPUs, reduce parallelism or scale out", c.Value),
			})
		case "cpu.softirq":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("High softirq CPU: %s — network interrupt storm or packet flood", c.Value),
			})
		}
	}

	return actions
}

func memActions(result *model.AnalysisResult, primary *model.RCAEntry) []model.Action {
	var actions []model.Action

	// Show top memory owners
	if len(result.MemOwners) > 0 {
		var top []string
		for i, o := range result.MemOwners {
			if i >= 3 {
				break
			}
			if o.PID > 0 {
				top = append(top, fmt.Sprintf("%s(PID %d) %s", o.Name, o.PID, o.Value))
			} else {
				top = append(top, fmt.Sprintf("%s %s", o.Name, o.Value))
			}
		}
		actions = append(actions, model.Action{
			Summary: fmt.Sprintf("Top memory consumers: %s", strings.Join(top, ", ")),
		})
	}

	if primary == nil {
		return actions
	}

	for _, c := range primary.Checks {
		if !c.Passed {
			continue
		}
		switch c.Group {
		case "mem.swap.activity":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Active swapping: %s — system is thrashing, reduce memory usage or add RAM", c.Value),
			})
		case "mem.reclaim.direct":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Direct reclaim active: %s — kernel stalling to free memory", c.Value),
			})
		case "mem.oom.kills":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("OOM kills occurred: %s — processes being killed by kernel", c.Value),
			})
		case "mem.available.low":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Available memory critically low: %s — risk of OOM", c.Value),
			})
		}
	}

	return actions
}

func ioActions(result *model.AnalysisResult, primary *model.RCAEntry) []model.Action {
	var actions []model.Action

	// Show top IO owners
	if len(result.IOOwners) > 0 {
		var top []string
		for i, o := range result.IOOwners {
			if i >= 3 {
				break
			}
			if o.PID > 0 {
				top = append(top, fmt.Sprintf("%s(PID %d) %s", o.Name, o.PID, o.Value))
			} else {
				top = append(top, fmt.Sprintf("%s %s", o.Name, o.Value))
			}
		}
		actions = append(actions, model.Action{
			Summary: fmt.Sprintf("Top IO consumers: %s", strings.Join(top, ", ")),
		})
	}

	if primary == nil {
		return actions
	}

	for _, c := range primary.Checks {
		if !c.Passed {
			continue
		}
		switch c.Group {
		case "io.fsfull":
			// Show actual filesystem data from DiskGuard
			if len(result.DiskGuardMounts) > 0 {
				for _, m := range result.DiskGuardMounts {
					if m.State == "CRIT" || m.State == "WARN" {
						eta := "stable"
						if m.ETASeconds > 0 {
							eta = fmt.Sprintf("~%.0fm to full", m.ETASeconds/60)
						}
						actions = append(actions, model.Action{
							Summary: fmt.Sprintf("Filesystem %s at %.1f%% used (%s) — %s",
								m.MountPoint, m.UsedPct, m.Device, eta),
						})
					}
				}
			} else {
				actions = append(actions, model.Action{
					Summary: fmt.Sprintf("Filesystem pressure: %s — check DiskGuard page (D)", c.Value),
				})
			}
		case "io.writeback":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Heavy dirty page writeback: %s — large write burst or flushing backlog", c.Value),
			})
		case "io.latency":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("High disk latency: %s — storage overloaded, check IOPS limits", c.Value),
			})
		case "io.dstate":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Processes stuck in D-state (uninterruptible IO): %s", c.Value),
			})
		}
	}

	return actions
}

func netActions(result *model.AnalysisResult, primary *model.RCAEntry) []model.Action {
	var actions []model.Action

	// Show top net owners
	if len(result.NetOwners) > 0 {
		var top []string
		for i, o := range result.NetOwners {
			if i >= 3 {
				break
			}
			top = append(top, fmt.Sprintf("%s %s", o.Name, o.Value))
		}
		actions = append(actions, model.Action{
			Summary: fmt.Sprintf("Top network consumers: %s", strings.Join(top, ", ")),
		})
	}

	if primary == nil {
		return actions
	}

	for _, c := range primary.Checks {
		if !c.Passed {
			continue
		}
		switch c.Group {
		case "net.drops":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Packet drops detected: %s — NIC ring buffer overflow or backpressure", c.Value),
			})
		case "net.retrans":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("TCP retransmissions: %s — network congestion or remote host issues", c.Value),
			})
		case "net.conntrack":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Conntrack table pressure: %s — nf_conntrack_max may need increase", c.Value),
			})
		case "net.tcp.state":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("TCP state anomaly: %s — TIME_WAIT accumulation or SYN backlog", c.Value),
			})
		case "net.closewait":
			cwSummary := fmt.Sprintf("CLOSE_WAIT leak: %s", c.Value)
			if len(result.CloseWaitLeakers) > 0 {
				top := result.CloseWaitLeakers[0]
				cwSummary = fmt.Sprintf("CLOSE_WAIT leak: %s (PID %d) holding %d stale sockets, oldest %s — app not calling close()",
					top.Comm, top.PID, top.Count, fmtAge(top.OldestAge))
			}
			actions = append(actions, model.Action{
				Summary: cwSummary,
			})
		case "net.errors":
			actions = append(actions, model.Action{
				Summary: fmt.Sprintf("Interface errors: %s — check cable/NIC health", c.Value),
			})
		}
	}

	return actions
}

func exhaustionAction(ex model.ExhaustionPrediction) model.Action {
	switch ex.Resource {
	case "Memory":
		return model.Action{
			Summary: fmt.Sprintf("Memory exhaustion in ~%.0fm (%.1f%% used, growing %.2f%%/s) — identify growing process or add RAM",
				ex.EstMinutes, ex.CurrentPct, ex.TrendPerS),
		}
	case "Swap":
		return model.Action{
			Summary: fmt.Sprintf("Swap exhaustion in ~%.0fm (%.1f%% used) — reduce memory pressure to stop swapping",
				ex.EstMinutes, ex.CurrentPct),
		}
	case "Ephemeral ports":
		return model.Action{
			Summary: fmt.Sprintf("Port exhaustion in ~%.0fm (%.1f%% used) — connection churn too high, check TIME_WAIT accumulation",
				ex.EstMinutes, ex.CurrentPct),
		}
	case "File descriptors":
		return model.Action{
			Summary: fmt.Sprintf("FD exhaustion in ~%.0fm (%.1f%% used) — file descriptor leak in progress",
				ex.EstMinutes, ex.CurrentPct),
		}
	case "CLOSE_WAIT sockets":
		return model.Action{
			Summary: fmt.Sprintf("CLOSE_WAIT growing — %.0f sockets at +%.1f/s, will exhaust FDs. Check Network page (4)",
				ex.CurrentPct, ex.TrendPerS),
		}
	default:
		if strings.HasPrefix(ex.Resource, "Disk ") {
			mount := strings.TrimPrefix(ex.Resource, "Disk ")
			return model.Action{
				Summary: fmt.Sprintf("Disk %s exhaustion in ~%.0fm (%.1f%% full) — see DiskGuard page (D) for top writers and big files",
					mount, ex.EstMinutes, ex.CurrentPct),
			}
		}
		return model.Action{
			Summary: fmt.Sprintf("%s exhaustion in ~%.0fm (%.1f%% used)", ex.Resource, ex.EstMinutes, ex.CurrentPct),
		}
	}
}

// knownService maps a process comm name to a known diagnosable service name.
// Returns "" if the process is not a recognized service.
func knownService(comm string) string {
	comm = strings.ToLower(comm)
	switch {
	case comm == "nginx" || comm == "nginx:" || strings.HasPrefix(comm, "nginx"):
		return "Nginx"
	case comm == "apache2" || comm == "httpd" || strings.HasPrefix(comm, "apache"):
		return "Apache"
	case comm == "mysqld" || comm == "mariadbd" || comm == "mysql":
		return "MySQL"
	case comm == "postgres" || strings.HasPrefix(comm, "postgres"):
		return "PostgreSQL"
	case comm == "redis-server" || comm == "redis" || strings.HasPrefix(comm, "redis"):
		return "Redis"
	case comm == "haproxy":
		return "HAProxy"
	case comm == "dockerd" || comm == "containerd" || comm == "docker":
		return "Docker"
	default:
		return ""
	}
}
