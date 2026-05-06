package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// runLoadshare implements `xtop loadshare` — explicit per-app load
// distribution. Shows each detected app's share of CPU / RAM / IO / network
// as both absolute values and percentage of system capacity.
//
// Designed to answer "is mongodb the dominant load on this box?" in one
// glance without scrolling through the TUI.
func runLoadshare(args []string) error {
	fs := flag.NewFlagSet("loadshare", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON instead of a table")
	sortBy := fs.String("sort", "impact", "sort key: impact|cpu|mem|io|net")
	limit := fs.Int("n", 20, "max apps to show")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop loadshare — per-app resource distribution

  xtop loadshare              table view, sorted by impact
  xtop loadshare --sort cpu   sort by CPU%
  xtop loadshare --json       JSON for scripting
  xtop loadshare -n 5         top 5 only

Each row shows what fraction of THIS host's CPU / RAM / IO / network the
app is responsible for. Use this when "the box feels slow" — a single
app dominating multiple dimensions is usually the answer.

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Need apps detection — must use rich mode.
	eng := engine.NewEngineMode(60, 3, collector.ModeRich)
	defer eng.Close()
	eng.Tick() // baseline
	snap, _, _ := eng.Tick()

	if snap == nil {
		return fmt.Errorf("failed to collect metrics")
	}

	apps := append([]model.AppInstance(nil), snap.Global.Apps.Instances...)
	if len(apps) == 0 {
		fmt.Println("No applications detected on this host.")
		fmt.Println("(xtop auto-detects MySQL/Postgres/MongoDB/Redis/nginx/Apache/HAProxy/")
		fmt.Println(" Memcached/Elasticsearch/Kafka/RabbitMQ/Docker/PHP-FPM/Plesk/Caddy/Traefik")
		fmt.Println(" by process comm. If yours is running but missing, file an issue with")
		fmt.Println(" the comm name from `ps -eo comm`.)")
		return nil
	}

	sortApps(apps, *sortBy)
	if *limit > 0 && len(apps) > *limit {
		apps = apps[:*limit]
	}

	if *jsonOut {
		return loadshareJSON(apps)
	}
	return loadshareTable(snap, apps)
}

func sortApps(apps []model.AppInstance, by string) {
	sort.SliceStable(apps, func(i, j int) bool {
		ai, aj := apps[i], apps[j]
		switch strings.ToLower(by) {
		case "cpu":
			return ai.Share.CPUPctOfSystem > aj.Share.CPUPctOfSystem
		case "mem":
			return ai.Share.MemPctOfSystem > aj.Share.MemPctOfSystem
		case "io":
			return (ai.Share.ReadMBs + ai.Share.WriteMBs) > (aj.Share.ReadMBs + aj.Share.WriteMBs)
		case "net":
			return ai.Share.NetConns > aj.Share.NetConns
		default:
			return ai.Share.Impact > aj.Share.Impact
		}
	})
}

func loadshareTable(snap *model.Snapshot, apps []model.AppInstance) error {
	nCPU := snap.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	memTotalGB := float64(snap.Global.Memory.Total) / (1024 * 1024 * 1024)

	fmt.Println()
	fmt.Printf("  %sxtop loadshare%s — %s\n", B, R, snap.Timestamp.Format("2006-01-02 15:04:05"))
	if snap.SysInfo != nil {
		fmt.Printf("  %s%s%s — %d CPUs, %.1f GB RAM\n",
			D, snap.SysInfo.Hostname, R, nCPU, memTotalGB)
	} else {
		fmt.Printf("  %d CPUs, %.1f GB RAM\n", nCPU, memTotalGB)
	}
	fmt.Println()

	// Table header
	fmt.Printf("  %s%-22s  %12s  %16s  %12s  %8s  %8s%s\n",
		B, "APP", "CPU%", "MEM (GB / %)", "IO MB/s", "CONNS", "IMPACT", R)
	fmt.Printf("  %s\n", strings.Repeat("─", 92))

	// Per-row
	for _, app := range apps {
		s := app.Share
		name := app.DisplayName
		if name == "" {
			name = app.AppType
		}
		if len(name) > 22 {
			name = name[:22]
		}
		cpuStr := fmt.Sprintf("%.1f%% (%.2f/%d)", s.CPUPctOfSystem, s.CPUCoresUsed, nCPU)
		memGB := float64(s.MemRSSBytes) / (1024 * 1024 * 1024)
		memStr := fmt.Sprintf("%.2f / %.1f%%", memGB, s.MemPctOfSystem)
		ioStr := fmt.Sprintf("R%.1f W%.1f", s.ReadMBs, s.WriteMBs)
		impactCol := colorByImpact(s.Impact)
		fmt.Printf("  %-22s  %12s  %16s  %12s  %8d  %8s\n",
			name, cpuStr, memStr, ioStr, s.NetConns, impactCol)
	}

	fmt.Println()
	// Show "rest of system" = what's left after the listed apps consume their share
	var totalCPU, totalMem float64
	for _, app := range apps {
		totalCPU += app.Share.CPUPctOfSystem
		totalMem += app.Share.MemPctOfSystem
	}
	if totalCPU > 0 || totalMem > 0 {
		restCPU := 100.0 - totalCPU
		if restCPU < 0 {
			restCPU = 0
		}
		restMem := 100.0 - totalMem
		if restMem < 0 {
			restMem = 0
		}
		fmt.Printf("  %sCovered by listed apps:%s CPU %.1f%%, MEM %.1f%%\n",
			D, R, totalCPU, totalMem)
		fmt.Printf("  %sRemainder (kernel + other procs):%s CPU %.1f%%, MEM %.1f%%\n",
			D, R, restCPU, restMem)
		fmt.Println()
	}

	// Highlight: if one app dominates, name it
	if len(apps) > 0 {
		top := apps[0]
		if top.Share.CPUPctOfSystem > 50 || top.Share.MemPctOfSystem > 50 {
			fmt.Printf("  %sDOMINANT LOAD:%s %s — %.0f%% of CPU, %.0f%% of RAM. ",
				FBYel, R, top.DisplayName,
				top.Share.CPUPctOfSystem, top.Share.MemPctOfSystem)
			fmt.Printf("If this host feels slow, this is why.\n\n")
		} else if top.Share.Impact >= 50 {
			fmt.Printf("  %sTOP IMPACT:%s %s (impact %.0f). Look here first when investigating slowdowns.\n\n",
				FCyn, R, top.DisplayName, top.Share.Impact)
		}
	}
	return nil
}

func loadshareJSON(apps []model.AppInstance) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{"apps": apps})
}
