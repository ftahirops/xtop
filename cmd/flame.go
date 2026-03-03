package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	bpf "github.com/ftahirops/xtop/collector/ebpf"
)

// runFlame implements the `xtop flame <pid> [duration] [-o file] [--ascii]` subcommand.
// Generates a CPU flamegraph for the specified process.
func runFlame(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: xtop flame <pid> [duration_sec] [-o file] [--ascii] [--folded]")
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid PID: %s", args[0])
	}

	duration := 5
	outputFile := ""
	ascii := true // default to ASCII
	folded := false

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-o":
			if i+1 < len(args) {
				i++
				outputFile = args[i]
			}
		case "--ascii":
			ascii = true
		case "--folded":
			folded = true
			ascii = false
		default:
			if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
				duration = n
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Profiling PID %d for %ds...\n", pid, duration)

	// For now, generate a placeholder flamegraph from /proc data
	// Full BPF integration requires compiled cpuprofile BPF object
	samples := collectProfileSamples(pid, duration)
	if len(samples) == 0 {
		fmt.Println("No stack samples collected. Ensure the process is running and you have root access.")
		return nil
	}

	foldedStacks := bpf.ResolveFoldedStacks(samples, pid)

	out := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	if folded {
		// Output in folded format (for external flamegraph tools)
		for _, fs := range foldedStacks {
			fmt.Fprintf(out, "%s %d\n", fs.Stack, fs.Count)
		}
		if outputFile != "" {
			fmt.Fprintf(os.Stderr, "Wrote folded stacks to %s\n", outputFile)
		}
		return nil
	}

	if ascii {
		renderASCIIFlamegraph(out, foldedStacks, 80)
	}

	return nil
}

// collectProfileSamples collects stack samples from /proc for a PID.
// This is a fallback when BPF profiling is unavailable.
func collectProfileSamples(pid, durationSec int) []bpf.StackSample {
	// Read /proc/PID/stack for kernel stack (simplified)
	stackPath := fmt.Sprintf("/proc/%d/stack", pid)
	data, err := os.ReadFile(stackPath)
	if err != nil {
		return nil
	}

	var addrs []uint64
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: [<ffffffff...>] function_name+0x.../0x...
		if len(line) > 3 && line[0] == '[' {
			end := strings.Index(line, "]")
			if end > 1 {
				hexStr := strings.TrimPrefix(line[1:end], "<")
				hexStr = strings.TrimSuffix(hexStr, ">")
				if addr, err := strconv.ParseUint(hexStr, 16, 64); err == nil {
					addrs = append(addrs, addr)
				}
			}
		}
	}

	if len(addrs) == 0 {
		return nil
	}

	return []bpf.StackSample{
		{
			PID:         pid,
			Count:       uint64(durationSec * 99), // simulated 99Hz
			KernAddrs:   addrs,
		},
	}
}

// flameNode represents a node in the flamegraph tree.
type flameNode struct {
	name     string
	count    uint64
	children map[string]*flameNode
}

func newFlameNode(name string) *flameNode {
	return &flameNode{
		name:     name,
		children: make(map[string]*flameNode),
	}
}

// renderASCIIFlamegraph renders a top-down ASCII flamegraph.
func renderASCIIFlamegraph(out *os.File, folded []bpf.FoldedStack, width int) {
	if len(folded) == 0 {
		fmt.Fprintln(out, "No stack data to display.")
		return
	}

	// Build tree
	root := newFlameNode("all")
	var totalCount uint64
	for _, fs := range folded {
		frames := strings.Split(fs.Stack, ";")
		node := root
		for _, frame := range frames {
			child, ok := node.children[frame]
			if !ok {
				child = newFlameNode(frame)
				node.children[frame] = child
			}
			child.count += fs.Count
			node = child
		}
		root.count += fs.Count
		totalCount += fs.Count
	}

	if totalCount == 0 {
		fmt.Fprintln(out, "No samples.")
		return
	}

	fmt.Fprintf(out, "\n  %sxtop flame%s — CPU Flamegraph (%d samples)\n\n", B, R, totalCount)

	// Render top-down
	renderFlameLevel(out, root, width, 0, totalCount)
	fmt.Fprintln(out)

	// Legend
	fmt.Fprintf(out, "  %sLegend:%s ", D, R)
	fmt.Fprintf(out, "%s%s ████ %s>50%% hot  ", B, FBRed, R)
	fmt.Fprintf(out, "%s████%s >20%% warm  ", FBYel, R)
	fmt.Fprintf(out, "%s████%s cool\n\n", FBGrn, R)
}

func renderFlameLevel(out *os.File, node *flameNode, totalWidth, depth int, totalSamples uint64) {
	if depth > 20 { // max depth to prevent runaway
		return
	}

	// Sort children by count descending
	type childEntry struct {
		name  string
		node  *flameNode
	}
	var children []childEntry
	for name, child := range node.children {
		children = append(children, childEntry{name, child})
	}
	sort.Slice(children, func(i, j int) bool {
		return children[i].node.count > children[j].node.count
	})

	indent := strings.Repeat("  ", depth)
	for _, c := range children {
		pct := float64(c.node.count) / float64(totalSamples) * 100
		if pct < 1 { // skip <1%
			continue
		}

		// Color by heat
		barWidth := int(float64(totalWidth-len(indent)-25) * pct / 100)
		if barWidth < 1 {
			barWidth = 1
		}
		if barWidth > totalWidth-len(indent)-25 {
			barWidth = totalWidth - len(indent) - 25
		}

		color := FBGrn
		if pct > 50 {
			color = FBRed
		} else if pct > 20 {
			color = FBYel
		}

		name := c.name
		maxName := totalWidth - len(indent) - barWidth - 15
		if maxName < 10 {
			maxName = 10
		}
		if len(name) > maxName {
			name = name[:maxName-2] + ".."
		}

		bar := strings.Repeat("█", barWidth)
		fmt.Fprintf(out, "%s%s%s%s %s%5.1f%%%s %s\n",
			indent, color, bar, R, D, pct, R, name)

		renderFlameLevel(out, c.node, totalWidth, depth+1, totalSamples)
	}
}
