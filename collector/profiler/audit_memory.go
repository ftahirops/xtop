//go:build linux

package profiler

import (
	"fmt"
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

	result := evalSysctlRules(rules, role)

	// Transparent Huge Pages check
	thpEnabled, _ := util.ReadFileString("/sys/kernel/mm/transparent_hugepage/enabled")
	thpEnabled = strings.TrimSpace(thpEnabled)
	thpStatus := extractBracketValue(thpEnabled)
	switch role {
	case model.RoleDatabase:
		// THP should be disabled for databases (causes latency spikes)
		status := model.RulePass
		rec := "never"
		if thpStatus != "never" && thpStatus != "madvise" {
			status = model.RuleFail
			rec = "never (THP causes latency spikes in databases)"
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "transparent_hugepages",
			Description: "Transparent Huge Pages allocation",
			Current:     thpStatus,
			Recommended: rec,
			Impact:      "Latency spikes from THP compaction in database workloads",
			Status:      status,
			Weight:      10,
		})
	case model.RoleHypervisor:
		// THP is generally beneficial for hypervisors
		status := model.RulePass
		if thpStatus == "never" {
			status = model.RuleWarn
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "transparent_hugepages",
			Description: "Transparent Huge Pages allocation",
			Current:     thpStatus,
			Recommended: "always or madvise",
			Impact:      "Missing THP benefit for VM memory management",
			Status:      status,
			Weight:      5,
		})
	}

	// KSM check for hypervisors
	if role == model.RoleHypervisor {
		ksmRun, _ := util.ReadFileString("/sys/kernel/mm/ksm/run")
		ksmRun = strings.TrimSpace(ksmRun)
		status := model.RulePass
		if ksmRun != "1" {
			status = model.RuleWarn
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "ksm",
			Description: "Kernel Same-page Merging (deduplication for VMs)",
			Current:     ksmRun,
			Recommended: "1 (enabled)",
			Impact:      "Missing memory deduplication across VMs",
			Status:      status,
			Weight:      5,
		})
	}

	// Check swap space existence
	if snap.Global.Memory.SwapTotal == 0 {
		status := model.RuleWarn
		if role == model.RoleHypervisor {
			status = model.RulePass // no swap is fine on hypervisors
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainMemory,
			Name:        "swap_space",
			Description: "Swap space configured",
			Current:     "0 (no swap)",
			Recommended: "1-2x RAM or at least a small swap file",
			Impact:      "OOM kills instead of graceful degradation under memory pressure",
			Status:      status,
			Weight:      5,
		})
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
