package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ModuleTier classifies each collector by cost and how essential it is to
// the RCA core. The toggle UI groups by tier so operators can flip whole
// bands on/off without picking 26 individual checkboxes.
type ModuleTier int

const (
	TierEssential ModuleTier = iota // can't disable; RCA breaks without these
	TierStandard                    // recommended; light cost
	TierOptional                    // medium cost; opt-in features
	TierHeavy                       // high cost; only enable during investigation
)

func (t ModuleTier) String() string {
	switch t {
	case TierEssential:
		return "essential"
	case TierStandard:
		return "standard"
	case TierOptional:
		return "optional"
	case TierHeavy:
		return "heavy"
	}
	return "unknown"
}

// ParseModuleTier accepts the four tier names + their stems (case-insensitive).
func ParseModuleTier(s string) (ModuleTier, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "essential", "ess":
		return TierEssential, true
	case "standard", "std":
		return TierStandard, true
	case "optional", "opt":
		return TierOptional, true
	case "heavy", "hvy":
		return TierHeavy, true
	}
	return 0, false
}

// ModuleInfo describes one toggleable module to the UI / config layer.
// Name matches the collector's Name() string for the registry-side toggle.
// CostHint is a short description ("light: cached after first scan",
// "HIGH: walks ENTIRE filesystem") shown in the toggle panel.
type ModuleInfo struct {
	Name        string
	Tier        ModuleTier
	CostHint    string
	Description string
}

// moduleCatalog is the authoritative list of every module xtop can run,
// with its tier + cost hint. Adding a new collector requires a new entry
// here so the toggle panel knows what to show. Keep in sync with
// richCollectors() / leanCollectors() / engine.NewEngineMode.
var moduleCatalog = []ModuleInfo{
	// ── ESSENTIAL — RCA core, never disabled ─────────────────────────────
	{Name: "sysinfo", Tier: TierEssential, CostHint: "negligible", Description: "Hostname, kernel, OS — read once at startup"},
	{Name: "psi", Tier: TierEssential, CostHint: "3 small reads", Description: "/proc/pressure/{cpu,memory,io} — primary RCA signal"},
	{Name: "cpu", Tier: TierEssential, CostHint: "2 small reads", Description: "/proc/stat + loadavg"},
	{Name: "memory", Tier: TierEssential, CostHint: "1 read", Description: "/proc/meminfo"},
	{Name: "disk", Tier: TierEssential, CostHint: "5 reads", Description: "/proc/diskstats per device"},
	{Name: "network", Tier: TierEssential, CostHint: "4 reads", Description: "Basic interface counters + sockstat"},
	{Name: "filesystem", Tier: TierEssential, CostHint: "1 statfs/mount", Description: "Mount usage + free space"},
	{Name: "process", Tier: TierEssential, CostHint: "/proc walk", Description: "Top-N processes for culprit attribution"},
	{Name: "identity", Tier: TierEssential, CostHint: "cached", Description: "System ID + persistent agent UUID"},

	// ── STANDARD — recommended, light cost ──────────────────────────────
	{Name: "cgroup", Tier: TierStandard, CostHint: "1 dirent walk", Description: "systemd unit + container cgroup roll-ups"},
	{Name: "runtime", Tier: TierStandard, CostHint: "cached per PID", Description: ".NET / JVM / Python / Node / Go runtime detection"},
	{Name: "apps", Tier: TierStandard, CostHint: "30s detection cycle", Description: "Auto-detect MySQL / Redis / nginx / etc and basic health"},
	{Name: "socket", Tier: TierStandard, CostHint: "few reads", Description: "TCP/UDP table summaries"},
	{Name: "softirq", Tier: TierStandard, CostHint: "1 read", Description: "/proc/softirqs — kernel softirq distribution"},

	// ── OPTIONAL — medium cost, opt-in ───────────────────────────────────
	{Name: "ebpf-sentinel", Tier: TierOptional, CostHint: "kernel maps + ring-buffer", Description: "Always-on eBPF probes (kfreeskb, oomkill, retransmit, etc.)"},
	{Name: "smart", Tier: TierOptional, CostHint: "shells out every 5min", Description: "Disk wear/temperature via smartctl"},
	{Name: "gpu", Tier: TierOptional, CostHint: "shells out", Description: "NVIDIA GPU metrics via nvidia-smi"},
	{Name: "sysctl", Tier: TierOptional, CostHint: "key kernel params", Description: "Critical sysctl values (mostly static)"},
	{Name: "logs", Tier: TierOptional, CostHint: "during incident only", Description: "Recent kernel + journald lines"},
	{Name: "healthcheck", Tier: TierOptional, CostHint: "during incident", Description: "TCP probes against detected app ports"},
	{Name: "diag", Tier: TierOptional, CostHint: "15s interval", Description: "Per-service deep diagnostics (overlap with app-doctor)"},
	{Name: "security", Tier: TierOptional, CostHint: "audit.log scan", Description: "Auth, login history, capability surface"},

	// ── HEAVY — only enable during investigation ─────────────────────────
	{Name: "deleted-open", Tier: TierHeavy, CostHint: "walks /proc/*/fd", Description: "Detect processes holding deleted file descriptors"},
	{Name: "fileless", Tier: TierHeavy, CostHint: "walks /proc/*/maps", Description: "Detect anonymous executable mappings (security)"},
	{Name: "bigfiles", Tier: TierHeavy, CostHint: "scans 9 dirs", Description: "Find files ≥ 50 MB (every 60s)"},
	{Name: "deep-scan", Tier: TierHeavy, CostHint: "FULL FILESYSTEM walk", Description: "ionice-IDLE walker; opt-in via XTOP_DEEP_SCAN=1"},
	{Name: "profiler", Tier: TierHeavy, CostHint: "role audit", Description: "System-role detection + full optimization audit"},
	{Name: "proxmox", Tier: TierHeavy, CostHint: "PVE-specific", Description: "Proxmox guest detection + per-VM stats (skip on non-PVE)"},
}

// ModuleCatalog returns a copy of the authoritative module list. Used by
// the UI to render the toggle panel and by config validation to reject
// unknown module names.
func ModuleCatalog() []ModuleInfo {
	out := make([]ModuleInfo, len(moduleCatalog))
	copy(out, moduleCatalog)
	return out
}

// ModuleConfig is the persisted operator preference. Disabled lists the
// names of modules the user explicitly turned off; Profile applies a
// preset on top (with explicit Disabled overriding the preset).
//
// Layered semantics:
//
//   1. Start from the Profile's default-enabled set ("Standard" by default).
//   2. Apply Profile's enable list — turns those on (no-op if already on).
//   3. Apply user's Disabled list — turns those off (final say).
//
// Result: simple users pick a profile and don't touch anything else;
// power users override individual modules.
type ModuleConfig struct {
	Profile    string    `json:"profile"`     // "minimal", "standard", "sre", "investigation"
	Disabled   []string  `json:"disabled"`    // explicit user opt-outs
	UpdatedAt  time.Time `json:"updated_at"`
}

// ModuleProfile describes one preset and the set of modules it enables.
type ModuleProfile struct {
	Name        string
	Description string
	// Enabled is the set of module names ON in this profile. Omitted
	// modules are off. Essential modules are always on regardless.
	Enabled []string
}

// builtinProfiles ships sensible defaults so 90% of operators never touch
// the toggle panel. "Standard" is the default; "Investigation" is
// time-bounded (UI auto-reverts after 60 min — see engine).
var builtinProfiles = []ModuleProfile{
	{
		Name:        "minimal",
		Description: "Lowest cost. Essential collectors only.",
		Enabled:     []string{}, // only Essential tier (always on)
	},
	{
		Name:        "standard",
		Description: "Recommended for fleet agents.",
		Enabled: []string{
			"cgroup", "runtime", "apps", "ebpf-sentinel",
		},
	},
	{
		Name:        "sre",
		Description: "Workstation / TUI. Everything except heavy probes.",
		Enabled: []string{
			"cgroup", "runtime", "apps", "ebpf-sentinel",
			"socket", "softirq", "smart", "gpu", "sysctl",
			"logs", "healthcheck", "diag", "security",
		},
	},
	{
		Name:        "investigation",
		Description: "Everything on. For active troubleshooting only.",
		Enabled:     allModuleNames(),
	},
}

func allModuleNames() []string {
	names := make([]string, 0, len(moduleCatalog))
	for _, m := range moduleCatalog {
		if m.Tier != TierEssential { // essentials are always on, no need to list
			names = append(names, m.Name)
		}
	}
	return names
}

// Profiles returns the built-in profile list. For UI rendering.
func Profiles() []ModuleProfile {
	out := make([]ModuleProfile, len(builtinProfiles))
	copy(out, builtinProfiles)
	return out
}

// FindProfile returns the named profile, or false if unknown.
func FindProfile(name string) (ModuleProfile, bool) {
	for _, p := range builtinProfiles {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return ModuleProfile{}, false
}

// ── Config persistence ───────────────────────────────────────────────────────

// ModuleConfigPath returns the on-disk location for the persisted config.
// Defaults to ~/.xtop/modules.json; respects $XTOP_MODULES_PATH for tests.
func ModuleConfigPath() string {
	if v := os.Getenv("XTOP_MODULES_PATH"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/xtop-modules.json"
	}
	return filepath.Join(home, ".xtop", "modules.json")
}

var moduleConfigMu sync.Mutex

// LoadModuleConfig reads the persisted config. Missing file → returns the
// default ("standard" profile, no disables) without error so the registry
// can boot cleanly on a fresh install.
func LoadModuleConfig() ModuleConfig {
	moduleConfigMu.Lock()
	defer moduleConfigMu.Unlock()
	path := ModuleConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return ModuleConfig{Profile: "standard"}
	}
	var c ModuleConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return ModuleConfig{Profile: "standard"}
	}
	if c.Profile == "" {
		c.Profile = "standard"
	}
	return c
}

// SaveModuleConfig writes the config atomically. Caller normally bumps
// UpdatedAt before saving so the panel shows "last edited 5m ago."
func SaveModuleConfig(c ModuleConfig) error {
	moduleConfigMu.Lock()
	defer moduleConfigMu.Unlock()
	path := ModuleConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now().UTC()
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// ── Resolution: config → enabled-set ────────────────────────────────────────

// ResolveEnabledModules returns the set of module names that should run
// after applying the profile + user overrides. Always includes Essential
// modules; never includes unknown names. Caller filters its collector
// list against this set.
func ResolveEnabledModules(c ModuleConfig) map[string]bool {
	enabled := make(map[string]bool, len(moduleCatalog))
	// Essentials are always on regardless of config.
	for _, m := range moduleCatalog {
		if m.Tier == TierEssential {
			enabled[m.Name] = true
		}
	}
	// Apply profile (default to standard if missing/unknown).
	prof, ok := FindProfile(c.Profile)
	if !ok {
		prof, _ = FindProfile("standard")
	}
	for _, n := range prof.Enabled {
		enabled[n] = true
	}
	// Apply user disables — explicit override over the profile, but
	// essentials still can't be turned off.
	for _, d := range c.Disabled {
		if t, found := tierOf(d); found && t != TierEssential {
			enabled[d] = false
		}
	}
	return enabled
}

func tierOf(name string) (ModuleTier, bool) {
	for _, m := range moduleCatalog {
		if m.Name == name {
			return m.Tier, true
		}
	}
	return 0, false
}

// FilterByConfig returns a slice of enabled-module names sorted by tier
// then name — a stable order for UI rendering.
func FilterByConfig(c ModuleConfig) []string {
	enabled := ResolveEnabledModules(c)
	var names []string
	for n, on := range enabled {
		if on {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		ti, _ := tierOf(names[i])
		tj, _ := tierOf(names[j])
		if ti != tj {
			return ti < tj
		}
		return names[i] < names[j]
	})
	return names
}

// SetProfile changes the active profile. Returns the previous profile name.
// Convenience wrapper used by the CLI subcommand and the TUI overlay.
func SetProfile(name string) (string, error) {
	prof, ok := FindProfile(name)
	if !ok {
		return "", fmt.Errorf("unknown profile %q (try: minimal, standard, sre, investigation)", name)
	}
	c := LoadModuleConfig()
	prev := c.Profile
	c.Profile = prof.Name
	c.UpdatedAt = time.Now().UTC()
	return prev, SaveModuleConfig(c)
}

// ToggleModule flips enabled/disabled for a specific module. Refuses to
// disable an Essential module — those are always on by design.
func ToggleModule(name string) (nowEnabled bool, err error) {
	tier, found := tierOf(name)
	if !found {
		return false, fmt.Errorf("unknown module %q", name)
	}
	if tier == TierEssential {
		return false, fmt.Errorf("module %q is Essential and cannot be disabled", name)
	}
	c := LoadModuleConfig()
	already := false
	for _, d := range c.Disabled {
		if d == name {
			already = true
			break
		}
	}
	if already {
		// remove from disabled list = re-enable
		var kept []string
		for _, d := range c.Disabled {
			if d != name {
				kept = append(kept, d)
			}
		}
		c.Disabled = kept
		c.UpdatedAt = time.Now().UTC()
		return true, SaveModuleConfig(c)
	}
	// add to disabled list
	c.Disabled = append(c.Disabled, name)
	c.UpdatedAt = time.Now().UTC()
	return false, SaveModuleConfig(c)
}
