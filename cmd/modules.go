package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ftahirops/xtop/collector"
)

// runModules dispatches `xtop modules <verb>` — the operator-facing CLI
// for the module-toggle feature. The TUI overlay (planned for v0.45.1)
// will edit the same config file, so any change made here is honored
// instantly by the next agent restart.
func runModules(args []string) error {
	if len(args) == 0 {
		return modulesShow(nil)
	}
	switch args[0] {
	case "show", "list", "ls":
		return modulesShow(args[1:])
	case "profile":
		return modulesProfile(args[1:])
	case "enable":
		return modulesToggle(args[1:], true)
	case "disable":
		return modulesToggle(args[1:], false)
	case "reset":
		return modulesReset()
	case "help", "-h", "--help":
		printModulesUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "xtop modules: unknown verb %q\n\n", args[0])
		printModulesUsage()
		return fmt.Errorf("unknown verb")
	}
}

func printModulesUsage() {
	fmt.Fprintln(os.Stderr, `xtop modules — toggle which collectors xtop runs

Subcommands:
  show                       Print current state — profile, enabled tier-by-tier.
  profile <name>             Switch to a profile: minimal | standard | sre | investigation
  enable <module-name>       Force-enable a module (overrides profile).
  disable <module-name>      Force-disable a module (overrides profile).
  reset                      Clear user overrides; revert to current profile defaults.

Profiles:
  minimal        Essential collectors only — lowest cost.
  standard       Recommended for fleet agents (default).
  sre            Workstation/TUI; everything except heavy investigation probes.
  investigation  Everything on; only enable while actively troubleshooting.

Config lives at ~/.xtop/modules.json. Changes apply on the next xtop
restart (TUI re-render or systemctl restart xtop-agent).`)
}

func modulesShow(_ []string) error {
	cfg := collector.LoadModuleConfig()
	enabled := collector.ResolveEnabledModules(cfg)
	prof := cfg.Profile
	if prof == "" {
		prof = "standard"
	}

	fmt.Printf("Profile: %s%s%s\n", B, prof, R)
	if !cfg.UpdatedAt.IsZero() {
		fmt.Printf("Last edited: %s\n", cfg.UpdatedAt.Local().Format("2006-01-02 15:04"))
	}
	if len(cfg.Disabled) > 0 {
		fmt.Printf("User overrides: disabled = %s\n", strings.Join(cfg.Disabled, ", "))
	}
	fmt.Println()

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%sTIER\tMODULE\tSTATE\tCOST HINT\tDESCRIPTION%s\n", B, R)
	fmt.Fprintf(tw, "----\t------\t-----\t---------\t-----------\n")

	cat := collector.ModuleCatalog()
	currentTier := collector.ModuleTier(-1)
	for _, m := range cat {
		if m.Tier != currentTier {
			currentTier = m.Tier
		}
		state := dimStyle("off")
		if enabled[m.Name] {
			state = okStyleStr("on")
		}
		if m.Tier == collector.TierEssential {
			state = okStyleStr("on (essential)")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			tierColored(m.Tier), m.Name, state, m.CostHint, m.Description)
	}
	tw.Flush()
	fmt.Println()
	fmt.Printf("Toggle a module: %sxtop modules disable <name>%s\n", B, R)
	fmt.Printf("Switch profile:  %sxtop modules profile sre%s\n", B, R)
	return nil
}

func modulesProfile(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: xtop modules profile <name>")
		fmt.Fprintln(os.Stderr, "available: minimal, standard, sre, investigation")
		return fmt.Errorf("missing profile name")
	}
	prev, err := collector.SetProfile(args[0])
	if err != nil {
		return err
	}
	if prev == args[0] {
		fmt.Printf("Already on profile %q.\n", args[0])
		return nil
	}
	fmt.Printf("Profile: %s → %s\n", prev, args[0])
	fmt.Println("Restart xtop / xtop-agent for changes to take effect:")
	fmt.Println("  sudo systemctl restart xtop-agent  (fleet agent)")
	return nil
}

func modulesToggle(args []string, enable bool) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: xtop modules enable|disable <module-name>")
		return fmt.Errorf("missing module name")
	}
	name := args[0]
	cfg := collector.LoadModuleConfig()
	currentlyDisabled := false
	for _, d := range cfg.Disabled {
		if d == name {
			currentlyDisabled = true
			break
		}
	}
	switch {
	case enable && !currentlyDisabled:
		fmt.Printf("Module %q is already enabled (or part of the active profile).\n", name)
		return nil
	case !enable && currentlyDisabled:
		fmt.Printf("Module %q is already in the disabled overrides.\n", name)
		return nil
	}
	nowOn, err := collector.ToggleModule(name)
	if err != nil {
		return err
	}
	if nowOn {
		fmt.Printf("Module %q: enabled (override removed).\n", name)
	} else {
		fmt.Printf("Module %q: disabled.\n", name)
	}
	fmt.Println("Restart xtop / xtop-agent for changes to take effect.")
	return nil
}

func modulesReset() error {
	cfg := collector.LoadModuleConfig()
	cfg.Disabled = nil
	if err := collector.SaveModuleConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("User overrides cleared. Profile remains %q.\n", cfg.Profile)
	return nil
}

// ── small UI helpers (no lipgloss dependency in cmd/) ───────────────────────

func okStyleStr(s string) string  { return "\033[32m" + s + "\033[0m" }

// dimStyle / B / R already exist in cmd/postmortem.go and friends.

func tierColored(t collector.ModuleTier) string {
	switch t {
	case collector.TierEssential:
		return "\033[32mEssential\033[0m"
	case collector.TierStandard:
		return "Standard"
	case collector.TierOptional:
		return "\033[33mOptional\033[0m"
	case collector.TierHeavy:
		return "\033[31mHeavy\033[0m"
	}
	return t.String()
}
