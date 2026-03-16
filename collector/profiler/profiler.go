//go:build linux

package profiler

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ProfilerCollector detects server role and audits configuration.
type ProfilerCollector struct {
	mu        sync.Mutex
	lastRun   time.Time
	cached    *model.ServerProfile
	interval  time.Duration
}

// NewProfilerCollector creates a new profiler.
func NewProfilerCollector() *ProfilerCollector {
	return &ProfilerCollector{
		interval: 60 * time.Second,
	}
}

func (p *ProfilerCollector) Name() string { return "profiler" }

func (p *ProfilerCollector) Collect(snap *model.Snapshot) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cached != nil && time.Since(p.lastRun) < p.interval {
		snap.Global.Profile = p.cached
		return nil
	}

	profile := &model.ServerProfile{}

	// Step 1: Detect server role
	profile.Role, profile.RoleDetail, profile.PanelName = detectRole(snap)

	// Step 2: Build service census from running processes
	profile.Services = buildServiceCensus(snap)

	// Step 3: Run audit rules per domain
	profile.Domains = runAudit(profile.Role, snap)

	// Step 4: Compute overall score
	totalWeight := 0
	totalWeightedScore := 0
	for _, d := range profile.Domains {
		w := domainWeight(d.Domain)
		totalWeight += w
		totalWeightedScore += d.Score * w
	}
	if totalWeight > 0 {
		profile.OverallScore = totalWeightedScore / totalWeight
	}

	p.cached = profile
	p.lastRun = time.Now()
	snap.Global.Profile = profile
	return nil
}

func domainWeight(d model.OptDomain) int {
	switch d {
	case model.OptDomainKernel:
		return 15
	case model.OptDomainNetwork:
		return 20
	case model.OptDomainMemory:
		return 20
	case model.OptDomainIO:
		return 15
	case model.OptDomainSecurity:
		return 15
	case model.OptDomainApps:
		return 15
	}
	return 10
}

func runAudit(role model.ServerRole, snap *model.Snapshot) []model.DomainScore {
	domains := []model.OptDomain{
		model.OptDomainKernel,
		model.OptDomainNetwork,
		model.OptDomainMemory,
		model.OptDomainIO,
		model.OptDomainSecurity,
		model.OptDomainApps,
	}

	var scores []model.DomainScore
	for _, d := range domains {
		var rules []model.AuditRule
		switch d {
		case model.OptDomainKernel:
			rules = auditKernel(role, snap)
		case model.OptDomainNetwork:
			rules = auditNetwork(role, snap)
		case model.OptDomainMemory:
			rules = auditMemory(role, snap)
		case model.OptDomainIO:
			rules = auditIO(role, snap)
		case model.OptDomainSecurity:
			rules = auditSecurity(role, snap)
		case model.OptDomainApps:
			rules = auditApps(role, snap)
		}

		score, issues := computeDomainScore(rules)
		scores = append(scores, model.DomainScore{
			Domain: d,
			Score:  score,
			Issues: issues,
			Rules:  rules,
		})
	}
	return scores
}

func computeDomainScore(rules []model.AuditRule) (int, int) {
	if len(rules) == 0 {
		return 100, 0
	}
	totalWeight := 0
	earnedWeight := 0
	issues := 0

	for _, r := range rules {
		if r.Status == model.RuleSkip {
			continue
		}
		totalWeight += r.Weight
		switch r.Status {
		case model.RulePass:
			earnedWeight += r.Weight
		case model.RuleWarn:
			earnedWeight += r.Weight / 2
			issues++
		case model.RuleFail:
			issues++
		}
	}
	if totalWeight == 0 {
		return 100, 0
	}
	return earnedWeight * 100 / totalWeight, issues
}

// buildServiceCensus groups processes by service and aggregates resource usage.
func buildServiceCensus(snap *model.Snapshot) []model.ServiceCensus {
	type svcAccum struct {
		display string
		cpu     float64
		rss     float64
		procs   int
		conns   int
	}
	m := make(map[string]*svcAccum)

	// Use detected apps for richer data
	for _, app := range snap.Global.Apps.Instances {
		key := app.AppType
		if key == "" {
			continue
		}
		a, ok := m[key]
		if !ok {
			a = &svcAccum{display: app.DisplayName}
			m[key] = a
		}
		a.cpu += app.CPUPct
		a.rss += app.RSSMB
		a.conns += app.Connections
		a.procs++
	}

	// Also scan top processes not covered by app detection
	knownComms := map[string]string{
		"mysqld": "mysql", "mariadbd": "mysql", "postgres": "postgresql",
		"mongod": "mongodb", "redis-server": "redis", "memcached": "memcached",
		"nginx": "nginx", "apache2": "apache", "httpd": "apache",
		"haproxy": "haproxy", "php-fpm": "php-fpm",
		"named": "bind", "unbound": "unbound",
		"postfix": "postfix", "dovecot": "dovecot", "exim4": "exim",
		"sshd": "sshd", "fail2ban-server": "fail2ban",
		"dockerd": "docker", "containerd": "containerd",
		"kubelet": "kubernetes", "etcd": "etcd",
		"java": "java", "node": "nodejs", "python3": "python", "python": "python",
		"pveproxy": "proxmox", "pvedaemon": "proxmox", "pvestatd": "proxmox",
	}

	uptimeSec := readSystemUptime()

	for _, proc := range snap.Processes {
		svcName, ok := knownComms[proc.Comm]
		if !ok {
			continue
		}
		if _, exists := m[svcName]; exists {
			continue // already covered by app detection
		}
		a, ok := m[svcName]
		if !ok {
			a = &svcAccum{display: svcName}
			m[svcName] = a
		}
		// Compute proper lifetime CPU% = (total_ticks / CLK_TCK) / uptime * 100
		totalTicks := proc.UTime + proc.STime
		if uptimeSec > 0 {
			a.cpu += float64(totalTicks) / 100.0 / float64(uptimeSec) * 100.0
		}
		a.rss += float64(proc.RSS) / (1024 * 1024)
		a.procs++
	}

	var result []model.ServiceCensus
	for name, a := range m {
		result = append(result, model.ServiceCensus{
			Name:        name,
			DisplayName: a.display,
			CPUPct:      a.cpu,
			RSSMB:       a.rss,
			Connections: a.conns,
			Processes:   a.procs,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CPUPct > result[j].CPUPct
	})
	if len(result) > 15 {
		result = result[:15]
	}
	return result
}

// readSystemUptime reads system uptime in seconds from /proc/uptime.
func readSystemUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

// readProcConnections counts established TCP connections for a PID via /proc/PID/net/tcp.
func readProcConnections(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	count := 0
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[3] == "01" { // 01 = ESTABLISHED
			count++
		}
	}
	return count
}
