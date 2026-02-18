package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	colorRed     = lipgloss.Color("#FF5555")
	colorYellow  = lipgloss.Color("#F1FA8C")
	colorGreen   = lipgloss.Color("#50FA7B")
	colorCyan    = lipgloss.Color("#8BE9FD")
	colorMagenta = lipgloss.Color("#FF79C6")
	colorOrange  = lipgloss.Color("#FFB86C")
	colorWhite   = lipgloss.Color("#F8F8F2")
	colorGray    = lipgloss.Color("#6272A4")
	colorPanel   = lipgloss.Color("#44475A")

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGray).
			Padding(0, 1)

	activePanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorCyan).
				Padding(0, 1)

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(colorCyan)
	labelStyle = lipgloss.NewStyle().Foreground(colorGray)
	valueStyle = lipgloss.NewStyle().Foreground(colorWhite)
	warnStyle  = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	critStyle  = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	okStyle    = lipgloss.NewStyle().Foreground(colorGreen)
	headerStyle = lipgloss.NewStyle().Foreground(colorMagenta).Bold(true)
	selectedStyle = lipgloss.NewStyle().Background(colorPanel).Foreground(colorWhite)
	helpStyle  = lipgloss.NewStyle().Foreground(colorGray)
	dimStyle   = lipgloss.NewStyle().Foreground(colorGray)
	orangeStyle = lipgloss.NewStyle().Foreground(colorOrange)
)

func scoreColor(score int) lipgloss.Style {
	switch {
	case score >= 60:
		return critStyle
	case score >= 30:
		return warnStyle
	default:
		return okStyle
	}
}

func pctColor(pct float64) lipgloss.Style {
	switch {
	case pct < 15:
		return critStyle
	case pct < 30:
		return warnStyle
	default:
		return okStyle
	}
}

func severityColor(sev string) lipgloss.Style {
	switch sev {
	case "crit":
		return critStyle
	case "warn":
		return warnStyle
	default:
		return orangeStyle
	}
}
