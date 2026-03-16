//go:build linux

package profiler

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

type sysctlRule struct {
	path        string
	name        string
	description string
	impact      string
	weight      int
	// recommend returns (recommended, status) based on current value and role
	recommend func(current string, role model.ServerRole) (string, model.RuleStatus)
}

func auditKernel(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	rules := []sysctlRule{
		{
			path: "/proc/sys/fs/file-max",
			name: "fs.file-max",
			description: "Maximum file descriptors system-wide",
			impact: "Connection drops and 'too many open files' errors",
			weight: 10,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				minVal := uint64(1000000)
				if role == model.RoleDatabase {
					minVal = 500000
				}
				if v >= minVal {
					return fmt.Sprintf(">=%d", minVal), model.RulePass
				}
				return fmt.Sprintf("%d", minVal), model.RuleFail
			},
		},
		{
			path: "/proc/sys/kernel/pid_max",
			name: "kernel.pid_max",
			description: "Maximum PID value",
			impact: "fork failures under heavy load",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v >= 4194304 {
					return "4194304", model.RulePass
				}
				if v >= 65536 {
					return "4194304", model.RuleWarn
				}
				return "4194304", model.RuleFail
			},
		},
		{
			path: "/proc/sys/kernel/threads-max",
			name: "kernel.threads-max",
			description: "Maximum threads system-wide",
			impact: "Thread creation failures under load",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v >= 100000 {
					return ">=100000", model.RulePass
				}
				return ">=100000", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/fs/inotify/max_user_watches",
			name: "fs.inotify.max_user_watches",
			description: "Maximum inotify watches per user",
			impact: "File monitoring failures (Docker, IDEs, bundlers)",
			weight: 3,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if role == model.RoleContainer || role == model.RoleWebHosting {
					if v >= 524288 {
						return "524288", model.RulePass
					}
					return "524288", model.RuleWarn
				}
				if v >= 65536 {
					return ">=65536", model.RulePass
				}
				return "524288", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/fs/inotify/max_user_instances",
			name: "fs.inotify.max_user_instances",
			description: "Maximum inotify instances per user",
			impact: "Cannot create new file watchers",
			weight: 3,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v >= 1024 {
					return ">=1024", model.RulePass
				}
				return "1024", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/kernel/panic",
			name: "kernel.panic",
			description: "Auto-reboot seconds after kernel panic (0=disabled)",
			impact: "Server stays hung after kernel panic instead of rebooting",
			weight: 5,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				v := parseUint(cur)
				if v > 0 && v <= 60 {
					return "10", model.RulePass
				}
				return "10", model.RuleWarn
			},
		},
		{
			path: "/proc/sys/kernel/panic_on_oops",
			name: "kernel.panic_on_oops",
			description: "Panic on kernel oops for faster recovery",
			impact: "Corrupt kernel state persists until manual reboot",
			weight: 3,
			recommend: func(cur string, role model.ServerRole) (string, model.RuleStatus) {
				if strings.TrimSpace(cur) == "1" {
					return "1", model.RulePass
				}
				return "1", model.RuleWarn
			},
		},
	}

	return evalSysctlRules(rules, role, model.OptDomainKernel)
}

func evalSysctlRules(rules []sysctlRule, role model.ServerRole, domain model.OptDomain) []model.AuditRule {
	var result []model.AuditRule
	for _, r := range rules {
		current, err := util.ReadFileString(r.path)
		if err != nil {
			continue // sysctl not available, skip
		}
		current = strings.TrimSpace(current)
		recommended, status := r.recommend(current, role)

		fix := ""
		if status != model.RulePass {
			recVal := extractFirstNumber(recommended)
			if recVal != "" {
				fix = fmt.Sprintf("sysctl -w %s=%s && echo '%s=%s' >> /etc/sysctl.d/99-xtop.conf", r.name, recVal, r.name, recVal)
			}
		}

		result = append(result, model.AuditRule{
			Domain:      domain,
			Name:        r.name,
			Description: r.description,
			Current:     current,
			Recommended: recommended,
			Impact:      r.impact,
			Fix:         fix,
			Status:      status,
			Weight:      r.weight,
		})
	}
	return result
}

func extractFirstNumber(s string) string {
	start := -1
	for i, c := range s {
		if c >= '0' && c <= '9' {
			if start < 0 {
				start = i
			}
		} else if start >= 0 {
			return s[start:i]
		}
	}
	if start >= 0 {
		return s[start:]
	}
	return ""
}

func parseUint(s string) uint64 {
	s = strings.TrimSpace(s)
	var v uint64
	fmt.Sscanf(s, "%d", &v)
	return v
}
