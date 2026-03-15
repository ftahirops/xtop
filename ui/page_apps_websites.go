//go:build linux

package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// renderWebsitesTable renders a per-website resource table.
// Shows top 5 active sites by CPU, with a count of hidden inactive sites.
// Used by Plesk, Nginx, Apache, and PHP-FPM detail views.
func renderWebsitesTable(websites []model.WebsiteMetrics, iw int) string {
	if len(websites) == 0 {
		return ""
	}

	// Separate active from inactive
	var active, inactive []model.WebsiteMetrics
	for _, w := range websites {
		if w.Active {
			active = append(active, w)
		} else {
			inactive = append(inactive, w)
		}
	}

	// Sort active by CPU descending
	sort.Slice(active, func(i, j int) bool {
		return active[i].CPUPct > active[j].CPUPct
	})

	// Show top 5 active + summary of rest
	showCount := 5
	if showCount > len(active) {
		showCount = len(active)
	}
	shown := active[:showCount]
	hiddenActive := len(active) - showCount
	hiddenInactive := len(inactive)

	var sb strings.Builder

	// Title
	title := fmt.Sprintf("ACTIVE WEBSITES (top %d", showCount)
	if hiddenActive > 0 {
		title += fmt.Sprintf(", %d more active", hiddenActive)
	}
	if hiddenInactive > 0 {
		title += fmt.Sprintf(", %d idle", hiddenInactive)
	}
	title += ")"

	sb.WriteString("\n")
	sb.WriteString(boxTopTitle(" "+titleStyle.Render(title)+" ", iw) + "\n")

	if len(shown) == 0 {
		sb.WriteString(boxRow("  "+dimStyle.Render("No active websites"), iw) + "\n")
		sb.WriteString(boxBot(iw) + "\n")
		return sb.String()
	}

	// Header
	colDom := 26
	colCPU := 7
	colRSS := 8
	colWrk := 9
	colHits := 8
	colDB := 8
	colDisk := 8

	header := fmt.Sprintf("  %s %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("DOMAIN"), colDom),
		styledPad(dimStyle.Render("CPU"), colCPU),
		styledPad(dimStyle.Render("RSS"), colRSS),
		styledPad(dimStyle.Render("Workers"), colWrk),
		styledPad(dimStyle.Render("Hits/m"), colHits),
		styledPad(dimStyle.Render("DB"), colDB),
		styledPad(dimStyle.Render("Disk"), colDisk),
		dimStyle.Render("PHP"))
	sb.WriteString(boxRow(header, iw) + "\n")
	sb.WriteString(boxRow("  "+dimStyle.Render(strings.Repeat("─", iw-4)), iw) + "\n")

	for _, w := range shown {
		domain := w.Domain
		if len(domain) > colDom-2 {
			domain = domain[:colDom-2]
		}

		// CPU color
		cpuStr := fmt.Sprintf("%.1f%%", w.CPUPct)
		var cpuStyled string
		if w.CPUPct > 50 {
			cpuStyled = critStyle.Render(cpuStr)
		} else if w.CPUPct > 20 {
			cpuStyled = warnStyle.Render(cpuStr)
		} else {
			cpuStyled = valueStyle.Render(cpuStr)
		}

		// RSS
		rssStr := fmtWebMB(w.RSSMB)

		// Workers
		wrkStr := fmt.Sprintf("%d", w.Workers)
		if w.MaxWorkers > 0 {
			wrkStr = fmt.Sprintf("%d/%d", w.Workers, w.MaxWorkers)
		}

		// Hits
		hitsStr := "—"
		if w.HitsPerMin > 0 {
			hitsStr = fmt.Sprintf("%d", w.HitsPerMin)
		}

		// DB
		dbStr := "—"
		if w.DBSizeMB > 0 {
			dbStr = fmtWebMB(w.DBSizeMB)
		}

		// Disk
		diskStr := "—"
		if w.DiskMB > 0 {
			diskStr = fmtWebMB(w.DiskMB)
		}

		// PHP
		phpStr := w.PHPVersion
		if phpStr == "" {
			phpStr = "—"
		}

		row := fmt.Sprintf("  %s %s %s %s %s %s %s %s",
			styledPad(valueStyle.Render(domain), colDom),
			styledPad(cpuStyled, colCPU),
			styledPad(valueStyle.Render(rssStr), colRSS),
			styledPad(valueStyle.Render(wrkStr), colWrk),
			styledPad(valueStyle.Render(hitsStr), colHits),
			styledPad(valueStyle.Render(dbStr), colDB),
			styledPad(valueStyle.Render(diskStr), colDisk),
			dimStyle.Render(phpStr))
		sb.WriteString(boxRow(row, iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}

func fmtWebMB(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fG", mb/1024)
	}
	if mb >= 1 {
		return fmt.Sprintf("%.0fM", mb)
	}
	if mb > 0 {
		return fmt.Sprintf("%.1fM", mb)
	}
	return "—"
}
