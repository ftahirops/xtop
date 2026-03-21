//go:build linux

package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/model"
)

func renderDockerDetail(app model.AppInstance, stackCursor int, stackExpanded []bool, containerIdx int, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	sb.WriteString(appDetailHeader(app))

	// ── Daemon overview (compact 2-column) ───────────────────────────
	leftW := iw/2 - 1
	var left strings.Builder
	left.WriteString(dimStyle.Render("DOCKER DAEMON") + "\n")
	for _, item := range []kv{
		{"Version", appFmtDash(app.Version)},
		{"PID", fmt.Sprintf("%d", app.PID)},
		{"Uptime", fmtUptime(app.UptimeSec)},
		{"Storage", dm["Storage Driver"]},
		{"Cgroup", dm["Cgroup Driver"]},
		{"OS", dm["OS"]},
		{"Kernel", dm["Kernel"]},
	} {
		if item.Val == "" {
			continue
		}
		left.WriteString(fmt.Sprintf(" %-10s %s\n", item.Key+":", valueStyle.Render(item.Val)))
	}
	var right strings.Builder
	running := dm["Running"]
	stopped := dm["Stopped"]
	paused := dm["Paused"]
	right.WriteString(dimStyle.Render("SUMMARY") + "\n")
	right.WriteString(fmt.Sprintf(" Containers: %s  Run: %s  Stop: %s  Pause: %s\n",
		valueStyle.Render(dm["Total Containers"]), okStyle.Render(running),
		dockerColorNonZero(stopped), dockerColorNonZero(paused)))
	right.WriteString(fmt.Sprintf(" Images: %s  Orch: %s\n",
		valueStyle.Render(dm["Images"]),
		dockerOrchBadge(app.OrchestrationType)))
	right.WriteString("\n")
	right.WriteString(dimStyle.Render("DISK") + "\n")
	if dm["images_total_size"] != "" {
		right.WriteString(fmt.Sprintf(" Images: %s", valueStyle.Render(dm["images_total_size"])))
		if dm["images_reclaimable"] != "" {
			right.WriteString(dimStyle.Render(" (rec: " + dm["images_reclaimable"] + ")"))
		}
		right.WriteString("\n")
	}
	if dm["volumes_count"] != "" {
		right.WriteString(fmt.Sprintf(" Volumes: %s (%s)\n",
			valueStyle.Render(dm["volumes_size"]), valueStyle.Render(dm["volumes_count"])))
	}
	if dm["containers_rw_size"] != "" {
		right.WriteString(fmt.Sprintf(" Writable: %s\n", valueStyle.Render(dm["containers_rw_size"])))
	}

	sb.WriteString(boxTop(iw) + "\n")
	combined := joinColumns(left.String(), right.String(), leftW, " \u2502 ")
	for _, line := range strings.Split(combined, "\n") {
		if line != "" {
			sb.WriteString(boxRow(line, iw) + "\n")
		}
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── Stack sections (collapsible) ─────────────────────────────────
	if len(app.Stacks) > 0 {
		sb.WriteString("\n  " + titleStyle.Render("STACKS") +
			"  " + dimStyle.Render(fmt.Sprintf("(%d stacks, %d containers)",
				len(app.Stacks), len(app.Containers))) + "\n\n")

		for i, stack := range app.Stacks {
			selected := i == stackCursor
			expanded := i < len(stackExpanded) && stackExpanded[i]

			// Stack header: ▶/▼ [badge] name — health — container count
			badge := dockerStackBadge(stack.Type)
			healthBadge := dockerStackHealthBadge(stack.HealthScore)
			summary := fmt.Sprintf("%s %s  %s  %s",
				badge, valueStyle.Render(stack.Name),
				healthBadge,
				dimStyle.Render(fmt.Sprintf("%d containers", len(stack.Containers))))
			if len(stack.Issues) > 0 {
				summary += "  " + warnStyle.Render(fmt.Sprintf("%d issues", len(stack.Issues)))
			}
			sb.WriteString(renderNetSectionHeader("", summary, selected, expanded, iw))

			if !expanded {
				continue
			}

			// Working dir / compose file
			if stack.WorkingDir != "" {
				sb.WriteString(boxTop(iw) + "\n")
				sb.WriteString(boxRow("  "+dimStyle.Render("Dir: ")+valueStyle.Render(stack.WorkingDir), iw) + "\n")
				if stack.ComposeFile != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("File: ")+valueStyle.Render(stack.ComposeFile), iw) + "\n")
				}
				sb.WriteString(boxMid(iw) + "\n")
			} else {
				sb.WriteString(boxTop(iw) + "\n")
			}

			// Container table
			cName := 20
			cState := 10
			cCPU := 7
			cMem := 9
			cMemPct := 5
			cNetRx := 9
			cNetTx := 9
			cBlkR := 9
			cBlkW := 9
			cRst := 4
			cImage := 24

			hdr := fmt.Sprintf(" %s%s%s%s%s%s%s%s%s%s%s",
				styledPad(dimStyle.Render("Name"), cName),
				styledPad(dimStyle.Render("State"), cState),
				styledPad(dimStyle.Render("CPU%"), cCPU),
				styledPad(dimStyle.Render("Mem"), cMem),
				styledPad(dimStyle.Render("Mem%"), cMemPct),
				styledPad(dimStyle.Render("Net RX"), cNetRx),
				styledPad(dimStyle.Render("Net TX"), cNetTx),
				styledPad(dimStyle.Render("Blk R"), cBlkR),
				styledPad(dimStyle.Render("Blk W"), cBlkW),
				styledPad(dimStyle.Render("Rst"), cRst),
				styledPad(dimStyle.Render("Image"), cImage))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")

			for _, c := range stack.Containers {
				name := c.Name
				if len(name) > cName-1 {
					name = name[:cName-4] + "..."
				}

				stateStr := dockerContainerStateStr(c)
				cpuStr := "—"
				memStr := "—"
				memPctStr := "—"
				netRx := "—"
				netTx := "—"
				blkR := "—"
				blkW := "—"
				rstStr := "—"

				if c.State == "running" {
					cpuStr = fmt.Sprintf("%.1f%%", c.CPUPct)
					if c.CPUPct > 80 {
						cpuStr = critStyle.Render(cpuStr)
					} else if c.CPUPct > 50 {
						cpuStr = warnStyle.Render(cpuStr)
					}
					memStr = appFmtBytesShort(c.MemUsedBytes)
					if c.MemLimitBytes > 0 && c.MemLimitBytes < 1e18 {
						memPctStr = fmt.Sprintf("%.0f%%", c.MemPct)
						if c.MemPct > 90 {
							memPctStr = critStyle.Render(memPctStr)
						} else if c.MemPct > 75 {
							memPctStr = warnStyle.Render(memPctStr)
						}
					}
					netRx = appFmtBytesShort(c.NetRxBytes)
					netTx = appFmtBytesShort(c.NetTxBytes)
					blkR = appFmtBytesShort(c.BlockRead)
					blkW = appFmtBytesShort(c.BlockWrite)
				}
				if c.RestartCount > 0 {
					rstStr = warnStyle.Render(fmt.Sprintf("%d", c.RestartCount))
				} else {
					rstStr = dimStyle.Render("0")
				}

				imageStr := c.Image
				if len(imageStr) > cImage-1 {
					imageStr = imageStr[:cImage-4] + "..."
				}

				row := fmt.Sprintf(" %s%s%s%s%s%s%s%s%s%s%s",
					styledPad(valueStyle.Render(name), cName),
					styledPad(stateStr, cState),
					styledPad(cpuStr, cCPU),
					styledPad(valueStyle.Render(memStr), cMem),
					styledPad(memPctStr, cMemPct),
					styledPad(valueStyle.Render(netRx), cNetRx),
					styledPad(valueStyle.Render(netTx), cNetTx),
					styledPad(valueStyle.Render(blkR), cBlkR),
					styledPad(valueStyle.Render(blkW), cBlkW),
					styledPad(rstStr, cRst),
					styledPad(dimStyle.Render(imageStr), cImage))
				sb.WriteString(boxRow(row, iw) + "\n")
			}

			// Published ports (compact, deduplicated, show public vs local)
			type portInfo struct {
				host, container int
				isPublic        bool
			}
			portKey := map[string]*portInfo{}
			var portOrder []string
			for _, c := range stack.Containers {
				for _, p := range c.Ports {
					if p.HostPort > 0 {
						key := fmt.Sprintf("%d:%d", p.HostPort, p.ContainerPort)
						if pi, ok := portKey[key]; ok {
							if dockerPortIsPublic(p.HostIP) {
								pi.isPublic = true
							}
						} else {
							portKey[key] = &portInfo{
								host: p.HostPort, container: p.ContainerPort,
								isPublic: dockerPortIsPublic(p.HostIP),
							}
							portOrder = append(portOrder, key)
						}
					}
				}
			}
			if len(portOrder) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				var portStrs []string
				for _, k := range portOrder {
					pi := portKey[k]
					label := fmt.Sprintf("%d→%d", pi.host, pi.container)
					if pi.isPublic {
						portStrs = append(portStrs, warnStyle.Render(label+" public"))
					} else {
						portStrs = append(portStrs, okStyle.Render(label+" local"))
					}
				}
				sb.WriteString(boxRow("  "+dimStyle.Render("Ports: ")+strings.Join(portStrs, "  "), iw) + "\n")
			}

			// Stack issues (diagnostics only)
			if len(stack.Issues) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				for _, issue := range stack.Issues {
					sb.WriteString(boxRow("  "+critStyle.Render("\u25cf")+" "+valueStyle.Render(issue), iw) + "\n")
				}
			}

			sb.WriteString(boxBot(iw) + "\n")
		}
	} else if len(app.Containers) > 0 {
		// Fallback: no stacks, just flat container list (shouldn't happen with new collector)
		sb.WriteString(renderDockerFlatContainers(app, iw))
	}

	sb.WriteString(pageFooter("j/k:Scroll  Tab:Section  Enter:Expand  A:All  C:Collapse  b:Back"))
	return sb.String()
}

// dockerContainerStateStr renders the state with health/restart indicators.
func dockerContainerStateStr(c model.AppDockerContainer) string {
	switch c.State {
	case "running":
		if c.Health == "unhealthy" {
			return critStyle.Render("unhealthy")
		} else if c.Health == "healthy" {
			return okStyle.Render("healthy")
		}
		return okStyle.Render("running")
	case "exited":
		if c.ExitCode != 0 {
			return critStyle.Render(fmt.Sprintf("exit:%d", c.ExitCode))
		}
		return dimStyle.Render("exited")
	case "paused":
		return warnStyle.Render("paused")
	default:
		return dimStyle.Render(c.State)
	}
}


// dockerStackBadge returns a colored badge for stack type.
func dockerStackBadge(stype string) string {
	switch stype {
	case "compose":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Render("[compose]")
	case "swarm":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Render("[swarm]")
	case "k8s":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("[k8s]")
	default:
		return dimStyle.Render("[standalone]")
	}
}

// dockerStackHealthBadge returns a colored health badge for a stack.
func dockerStackHealthBadge(score int) string {
	if score >= 80 {
		return okStyle.Render(fmt.Sprintf("H:%d", score))
	} else if score >= 50 {
		return warnStyle.Render(fmt.Sprintf("H:%d", score))
	}
	return critStyle.Render(fmt.Sprintf("H:%d", score))
}

// dockerOrchBadge renders the orchestration type.
func dockerOrchBadge(orch string) string {
	switch orch {
	case "compose":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Render("compose")
	case "swarm":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Render("swarm")
	case "k8s":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("k8s")
	case "mixed":
		return warnStyle.Render("mixed")
	default:
		return dimStyle.Render("standalone")
	}
}

// dockerColorNonZero colors non-zero values as warnings.
// dockerPortIsPublic returns true if the host IP binding is publicly accessible.
func dockerPortIsPublic(hostIP string) bool {
	return hostIP == "" || hostIP == "0.0.0.0" || hostIP == "::"
}

func dockerColorNonZero(s string) string {
	if s != "" && s != "0" {
		return warnStyle.Render(s)
	}
	return dimStyle.Render(s)
}

// truncStr truncates a string to maxLen with ellipsis.
func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 4 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// renderDockerFlatContainers is a fallback for when stacks aren't available.
func renderDockerFlatContainers(app model.AppInstance, iw int) string {
	var sb strings.Builder
	sb.WriteString("  " + titleStyle.Render("CONTAINERS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	for _, c := range app.Containers {
		name := c.Name
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		stateStr := dockerContainerStateStr(c)
		row := fmt.Sprintf(" %s  %s  CPU:%s  Mem:%s",
			styledPad(valueStyle.Render(name), 30),
			styledPad(stateStr, 10),
			valueStyle.Render(fmt.Sprintf("%.1f%%", c.CPUPct)),
			valueStyle.Render(appFmtBytesShort(c.MemUsedBytes)))
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}
