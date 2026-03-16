//go:build linux

package profiler

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

func auditMemory(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	rules := []sysctlRule{
		{
			path: "/proc/sys/vm/swappiness",
			name: "vm.swappiness",
			description: "Tendency to swap out memory pages (0-200)",
			impact: "Excessive swapping degrades performance",
			weight: 10,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				switch role {
				case model.RoleDatabase:
					if v <= 1 {
						return "1", model.RulePass
					}
					if v <= 10 {
						return "1", model.RuleWarn
					}
					return "1", model.RuleFail
				case model.RoleHypervisor:
					if v <= 10 {
						return "<=10", model.RulePass
					}
					return "10", model.RuleWarn
				default:
					if v <= 10 {
						return "<=10", model.RulePass
					}
					if v <= 30 {
						return "10", model.RuleWarn
					}
					return "10", model.RuleFail
				}
			},
		},
		{
			path: "/proc/sys/vm/dirty_ratio",
			name: "vm.dirty_ratio",
			description: "Maximum % of memory that can be dirty before blocking writes",
			impact: "IO stalls when dirty page limit reached",
			weight: 8,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				switch role {
				case model.RoleDatabase:
					if v <= 10 {
						return "<=10", model.RulePass
					}
					if v <= 20 {
						return "10", model.RuleWarn
					}
					return "10", model.RuleFail
				default:
					if v <= 20 {
						return "<=20", model.RulePass
					}
					if v <= 40 {
						return "20", model.RuleWarn
					}
					return "20", model.RuleFail
				}
			},
		},
		{
			path: "/proc/sys/vm/dirty_background_ratio",
			name: "vm.dirty_background_ratio",
			description: "% of memory at which background flushing starts",
			impact: "Write latency spikes from delayed flushing",
			weight: 8,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				switch role {
				case model.RoleDatabase:
					if v <= 5 {
						return "<=5", model.RulePass
					}
					return "5", model.RuleWarn
				default:
					if v <= 10 {
						return "<=10", model.RulePass
					}
					return "10", model.RuleWarn
				}
			},
		},
		{
			path: "/proc/sys/vm/overcommit_memory",
			name: "vm.overcommit_memory",
			description: "Memory overcommit policy (0=heuristic, 1=always, 2=strict)",
			impact: "OOM kills from overcommitted memory",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := strings.TrimSpace(cur)
				switch role {
				case model.RoleDatabase:
					// Databases prefer overcommit=2 to avoid OOM during large allocations
					if v == "2" {
						return "2 (strict)", model.RulePass
					}
					if v == "0" {
						return "2 (strict — recommended for DB)", model.RuleWarn
					}
					return "2 (strict)", model.RuleFail
				default:
					if v == "0" || v == "2" {
						return "0 or 2", model.RulePass
					}
					return "0 (heuristic)", model.RuleWarn
				}
			},
		},
		{
			path: "/proc/sys/vm/min_free_kbytes",
			name: "vm.min_free_kbytes",
			description: "Minimum free memory reserved for kernel (KB)",
			impact: "OOM kills and allocation failures under memory pressure",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				totalKB := snap.Global.Memory.Total / 1024
				// Should be at least 1% of RAM, capped at 2GB
				minRecommended := totalKB / 100
				if minRecommended > 2*1024*1024 {
					minRecommended = 2 * 1024 * 1024
				}
				if minRecommended < 65536 {
					minRecommended = 65536
				}
				if v >= minRecommended {
					return fmt.Sprintf(">=%d", minRecommended), model.RulePass
				}
				return fmt.Sprintf("%d (~1%% of RAM)", minRecommended), model.RuleWarn
			},
		},
	}

	result := evalSysctlRules(rules, role, model.OptDomainMemory)

	// Transparent Huge Pages check
	thpEnabled, _ := util.ReadFileString("/sys/kernel/mm/transparent_hugepage/enabled")
	thpEnabled = strings.TrimSpace(thpEnabled)
	thpStatus := extractBracketValue(thpEnabled)
	switch role {
	case model.RoleDatabase:
		// THP should be disabled for databases (causes latency spikes)
		status := model.RulePass
		rec := "never"
		thpFix := ""
		if thpStatus != "never" && thpStatus != "madvise" {
			status = model.RuleFail
			rec = "never (THP causes latency spikes in databases)"
			thpFix = "echo never > /sys/kernel/mm/transparent_hugepage/enabled"
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "transparent_hugepages",
			Description: "Transparent Huge Pages allocation",
			Current:     thpStatus,
			Recommended: rec,
			Impact:      "Latency spikes from THP compaction in database workloads",
			Fix:         thpFix,
			Status:      status,
			Weight:      10,
		})
	case model.RoleHypervisor:
		// THP is generally beneficial for hypervisors
		status := model.RulePass
		thpFix := ""
		if thpStatus == "never" {
			status = model.RuleWarn
			thpFix = "echo always > /sys/kernel/mm/transparent_hugepage/enabled"
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "transparent_hugepages",
			Description: "Transparent Huge Pages allocation",
			Current:     thpStatus,
			Recommended: "always or madvise",
			Impact:      "Missing THP benefit for VM memory management",
			Fix:         thpFix,
			Status:      status,
			Weight:      5,
		})
	}

	// KSM check for hypervisors
	if role == model.RoleHypervisor {
		ksmRun, _ := util.ReadFileString("/sys/kernel/mm/ksm/run")
		ksmRun = strings.TrimSpace(ksmRun)
		status := model.RulePass
		ksmFix := ""
		if ksmRun != "1" {
			status = model.RuleWarn
			ksmFix = "echo 1 > /sys/kernel/mm/ksm/run"
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "ksm",
			Description: "Kernel Same-page Merging (deduplication for VMs)",
			Current:     ksmRun,
			Recommended: "1 (enabled)",
			Impact:      "Missing memory deduplication across VMs",
			Fix:         ksmFix,
			Status:      status,
			Weight:      5,
		})
	}

	// Check swap space existence
	if snap.Global.Memory.SwapTotal == 0 {
		status := model.RuleWarn
		swapFix := "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile swap swap defaults 0 0' >> /etc/fstab"
		if role == model.RoleHypervisor {
			status = model.RulePass // no swap is fine on hypervisors
			swapFix = ""
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "swap_space",
			Description: "Swap space configured",
			Current:     "0 (no swap)",
			Recommended: "1-2x RAM or at least a small swap file",
			Impact:      "OOM kills instead of graceful degradation under memory pressure",
			Fix:         swapFix,
			Status:      status,
			Weight:      5,
		})
	}

	// Swap intelligence (when swap exists)
	if snap.Global.Memory.SwapTotal > 0 {
		// Check swap device type
		swapData, err := util.ReadFileString("/proc/swaps")
		if err == nil {
			for _, line := range strings.Split(swapData, "\n")[1:] {
				fields := strings.Fields(line)
				if len(fields) < 1 {
					continue
				}
				swapDev := fields[0]
				if strings.HasPrefix(swapDev, "/dev/sd") || strings.HasPrefix(swapDev, "/dev/hd") {
					devName := filepath.Base(swapDev)
					for len(devName) > 0 && devName[len(devName)-1] >= '0' && devName[len(devName)-1] <= '9' {
						devName = devName[:len(devName)-1]
					}
					rotPath := fmt.Sprintf("/sys/block/%s/queue/rotational", devName)
					if rot, rotErr := util.ReadFileString(rotPath); rotErr == nil && strings.TrimSpace(rot) == "1" {
						if role == model.RoleDatabase {
							result = append(result, model.AuditRule{
								Domain:      model.OptDomainMemory,
								Name:        "swap_device",
								Description: "Swap device type",
								Current:     swapDev + " (rotational/HDD)",
								Recommended: "SSD-backed swap for database servers",
								Impact:      "Swapping to HDD causes extreme latency for DB queries",
								Status:      model.RuleFail,
								Weight:      8,
							})
						}
					}
				}
			}
		}

		// Check zswap/zram
		zswapEnabled := false
		if data, zErr := util.ReadFileString("/sys/module/zswap/parameters/enabled"); zErr == nil {
			zswapEnabled = strings.TrimSpace(data) == "Y"
		}
		zramFound := false
		if matches, _ := filepath.Glob("/dev/zram*"); len(matches) > 0 {
			zramFound = true
		}
		if !zswapEnabled && !zramFound && role == model.RoleContainer {
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainMemory,
				Name:        "swap_compression",
				Description: "Swap compression (zswap/zram)",
				Current:     "not enabled",
				Recommended: "zswap or zram for container workloads",
				Impact:      "Uncompressed swap wastes IO bandwidth",
				Fix:         "echo 1 > /sys/module/zswap/parameters/enabled && echo 'zswap.enabled=1' >> /etc/default/grub",
				Status:      model.RuleWarn,
				Weight:      3,
			})
		}
	}

	return result
}

// extractBracketValue gets the active value from "[always] madvise never" format.
func extractBracketValue(s string) string {
	start := strings.Index(s, "[")
	end := strings.Index(s, "]")
	if start >= 0 && end > start {
		return s[start+1 : end]
	}
	return s
}
