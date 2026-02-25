package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/model"
)

// runDiagnose runs per-service deep diagnostics in CLI mode.
func runDiagnose(cfg Config) error {
	hostname, _ := os.Hostname()
	ts := time.Now().Format("2006-01-02")

	services := collector.DiagAll(cfg.DiagnoseTarget)

	if cfg.JSONMode {
		return renderDiagnoseJSON(services, hostname)
	}
	if cfg.MDMode {
		fmt.Println(renderDiagnoseMarkdown(services, hostname))
		return nil
	}

	renderDiagnoseCLI(services, hostname, ts)

	// Exit code based on worst severity
	worst := worstDiagSev(services)
	if worst == model.DiagCrit {
		return ExitCodeError{Code: 2}
	}
	if worst == model.DiagWarn {
		return ExitCodeError{Code: 1}
	}
	return nil
}

// ── CLI Output ──────────────────────────────────────────────────────────────

func renderDiagnoseCLI(services []model.ServiceDiag, hostname, ts string) {
	// Title bar
	fmt.Printf("\n %s%s xtop diagnose v%s %s — %s%s%s  %s%s%s\n\n",
		B, BBlu+FBWht, Version, R,
		B, hostname, R,
		D, ts, R)

	if len(services) == 0 {
		fmt.Printf(" %sNo services detected%s\n\n", D, R)
		return
	}

	totalWarn := 0
	totalCrit := 0
	totalSvc := len(services)

	for _, svc := range services {
		badge := cliSevBadge(svc.WorstSev)
		name := strings.ToUpper(svc.Name)
		padded := fmt.Sprintf("%-20s", name)
		fmt.Printf("== %s%s%s%s %s ==\n", B, FBWht, padded, R, badge)

		if len(svc.Findings) == 0 {
			fmt.Printf(" %s✓%s  No issues detected\n", FBGrn, R)
		}

		for _, f := range svc.Findings {
			icon := cliSevIcon(f.Severity)
			cat := fmt.Sprintf("%-10s", f.Category)
			line := fmt.Sprintf(" %s %s%s%s %s", icon, D, cat, R, f.Summary)
			if f.Advice != "" {
				line += fmt.Sprintf(" %s→ %s%s", D, f.Advice, R)
			}
			fmt.Println(line)

			switch f.Severity {
			case model.DiagWarn:
				totalWarn++
			case model.DiagCrit:
				totalCrit++
			}
		}
		fmt.Println()
	}

	// Summary line
	fmt.Println("---")
	var issues []string
	if totalCrit > 0 {
		issues = append(issues, fmt.Sprintf("%s%s%d critical%s", B, FBRed, totalCrit, R))
	}
	if totalWarn > 0 {
		issues = append(issues, fmt.Sprintf("%s%d warning(s)%s", FBYel, totalWarn, R))
	}
	if len(issues) == 0 {
		fmt.Printf(" %s✓ All clean across %d service(s)%s\n", FBGrn, totalSvc, R)
	} else {
		fmt.Printf(" %s across %d service(s)\n", strings.Join(issues, ", "), totalSvc)
	}
	fmt.Println()
}

func cliSevBadge(sev model.DiagSeverity) string {
	switch sev {
	case model.DiagCrit:
		return fmt.Sprintf("%s%sCRIT%s", B, FBRed, R)
	case model.DiagWarn:
		return fmt.Sprintf("%sWARN%s", FBYel, R)
	case model.DiagInfo:
		return fmt.Sprintf("%sINFO%s", FCyn, R)
	default:
		return fmt.Sprintf("%sOK%s", FBGrn, R)
	}
}

func cliSevIcon(sev model.DiagSeverity) string {
	switch sev {
	case model.DiagCrit:
		return fmt.Sprintf("%s%s!!%s", B, FBRed, R)
	case model.DiagWarn:
		return fmt.Sprintf("%s!!%s", FBYel, R)
	case model.DiagInfo:
		return fmt.Sprintf("%s i%s", FCyn, R)
	default:
		return fmt.Sprintf("%s +%s", FBGrn, R)
	}
}

// ── JSON Output ─────────────────────────────────────────────────────────────

type diagJSONReport struct {
	Timestamp string               `json:"timestamp"`
	Hostname  string               `json:"hostname"`
	Version   string               `json:"version"`
	Services  []diagJSONService    `json:"services"`
	Worst     string               `json:"worst_severity"`
}

type diagJSONService struct {
	Name     string             `json:"name"`
	Severity string             `json:"severity"`
	Metrics  map[string]string  `json:"metrics,omitempty"`
	Findings []diagJSONFinding  `json:"findings"`
}

type diagJSONFinding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Detail   string `json:"detail,omitempty"`
	Advice   string `json:"advice,omitempty"`
}

func renderDiagnoseJSON(services []model.ServiceDiag, hostname string) error {
	report := diagJSONReport{
		Timestamp: time.Now().Format(time.RFC3339),
		Hostname:  hostname,
		Version:   Version,
		Worst:     string(worstDiagSev(services)),
	}

	for _, svc := range services {
		js := diagJSONService{
			Name:     svc.Name,
			Severity: string(svc.WorstSev),
			Metrics:  svc.Metrics,
		}
		for _, f := range svc.Findings {
			js.Findings = append(js.Findings, diagJSONFinding{
				Severity: string(f.Severity),
				Category: f.Category,
				Summary:  f.Summary,
				Detail:   f.Detail,
				Advice:   f.Advice,
			})
		}
		report.Services = append(report.Services, js)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ── Markdown Output ─────────────────────────────────────────────────────────

func renderDiagnoseMarkdown(services []model.ServiceDiag, hostname string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# xtop Diagnose Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Host:** %s  \n", hostname))
	sb.WriteString(fmt.Sprintf("**Time:** %s  \n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Version:** %s\n\n", Version))

	if len(services) == 0 {
		sb.WriteString("No services detected.\n")
		return sb.String()
	}

	// Summary table
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Service | Status | Key Metrics |\n")
	sb.WriteString("|---------|--------|-------------|\n")
	for _, svc := range services {
		metrics := mdMetricsSummary(svc)
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
			svc.Name, strings.ToUpper(string(svc.WorstSev)), metrics))
	}
	sb.WriteString("\n")

	// Per-service findings
	for _, svc := range services {
		sb.WriteString(fmt.Sprintf("## %s — %s\n\n", strings.ToUpper(svc.Name[:1])+svc.Name[1:], strings.ToUpper(string(svc.WorstSev))))
		if len(svc.Findings) == 0 {
			sb.WriteString("No issues detected.\n\n")
			continue
		}
		for _, f := range svc.Findings {
			icon := mdSevIcon(f.Severity)
			line := fmt.Sprintf("- %s **%s**: %s", icon, f.Category, f.Summary)
			if f.Advice != "" {
				line += fmt.Sprintf(" — *%s*", f.Advice)
			}
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	// Totals
	worst := worstDiagSev(services)
	sb.WriteString(fmt.Sprintf("---\n**Overall:** %s across %d service(s)\n\n",
		strings.ToUpper(string(worst)), len(services)))
	sb.WriteString("*Generated by [xtop](https://github.com/ftahirops/xtop)*\n")
	return sb.String()
}

func mdSevIcon(sev model.DiagSeverity) string {
	switch sev {
	case model.DiagCrit:
		return "**[CRIT]**"
	case model.DiagWarn:
		return "**[WARN]**"
	case model.DiagInfo:
		return "[INFO]"
	default:
		return "[OK]"
	}
}

func mdMetricsSummary(svc model.ServiceDiag) string {
	var parts []string
	for k, v := range svc.Metrics {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func worstDiagSev(services []model.ServiceDiag) model.DiagSeverity {
	worst := model.DiagOK
	for _, svc := range services {
		if diagSevRank(svc.WorstSev) > diagSevRank(worst) {
			worst = svc.WorstSev
		}
	}
	return worst
}

func diagSevRank(s model.DiagSeverity) int {
	switch s {
	case model.DiagCrit:
		return 3
	case model.DiagWarn:
		return 2
	case model.DiagInfo:
		return 1
	default:
		return 0
	}
}
