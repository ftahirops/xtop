package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

// noColor is true when the NO_COLOR environment variable is set to a non-empty
// value (https://no-color.org). It is evaluated once at package init.
var noColor = os.Getenv("NO_COLOR") != ""

// fg returns c as a TerminalColor, or lipgloss.NoColor{} when NO_COLOR is set.
// Use this helper whenever building a style that carries a foreground or
// background color so that all color decisions flow through one gate.
func fg(c lipgloss.Color) lipgloss.TerminalColor {
	if noColor {
		return lipgloss.NoColor{}
	}
	return c
}

var (
	// Colors — kept as named constants; some callers reference them directly.
	// Pass through fg() when building styles so NO_COLOR is honoured.
	colorRed     = lipgloss.Color("#FF5555")
	colorYellow  = lipgloss.Color("#F1FA8C")
	colorGreen   = lipgloss.Color("#50FA7B")
	colorCyan    = lipgloss.Color("#8BE9FD")
	colorMagenta = lipgloss.Color("#FF79C6")
	colorOrange  = lipgloss.Color("#FFB86C")
	colorWhite   = lipgloss.Color("#F8F8F2")
	colorGray    = lipgloss.Color("#6272A4")
	colorPanel   = lipgloss.Color("#44475A")
)

// Style variables — initialised by initStyles() via init().
// Bold and Underline attributes are intentionally preserved even under NO_COLOR
// so that semantic signal (warn/crit/header) remains readable in monochrome.
var (
	panelStyle    lipgloss.Style
	activePanelStyle lipgloss.Style
	titleStyle    lipgloss.Style
	labelStyle    lipgloss.Style
	valueStyle    lipgloss.Style
	warnStyle     lipgloss.Style
	critStyle     lipgloss.Style
	okStyle       lipgloss.Style
	headerStyle   lipgloss.Style
	selectedStyle lipgloss.Style
	helpStyle     lipgloss.Style
	dimStyle      lipgloss.Style
	orangeStyle   lipgloss.Style
)

func init() {
	initStyles(noColor)
}

// initStyles builds all package-level styles. Pass noColor=true to strip every
// foreground/background color while keeping bold/underline for emphasis.
// Exposed for use in tests so both branches can be exercised deterministically.
func initStyles(nc bool) {
	// local alias so we don't shadow the package-level noColor during tests
	color := func(c lipgloss.Color) lipgloss.TerminalColor {
		if nc {
			return lipgloss.NoColor{}
		}
		return c
	}

	panelStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(color(colorGray)).
		Padding(0, 1)

	activePanelStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(color(colorCyan)).
		Padding(0, 1)

	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(color(colorCyan))
	labelStyle    = lipgloss.NewStyle().Foreground(color(colorGray))
	valueStyle    = lipgloss.NewStyle().Foreground(color(colorWhite))
	warnStyle     = lipgloss.NewStyle().Foreground(color(colorYellow)).Bold(true)
	critStyle     = lipgloss.NewStyle().Foreground(color(colorRed)).Bold(true)
	okStyle       = lipgloss.NewStyle().Foreground(color(colorGreen))
	headerStyle   = lipgloss.NewStyle().Foreground(color(colorMagenta)).Bold(true)
	selectedStyle = lipgloss.NewStyle().Background(color(colorPanel)).Foreground(color(colorWhite))
	helpStyle     = lipgloss.NewStyle().Foreground(color(colorGray))
	dimStyle      = lipgloss.NewStyle().Foreground(color(colorGray))
	orangeStyle   = lipgloss.NewStyle().Foreground(color(colorOrange))
}

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
