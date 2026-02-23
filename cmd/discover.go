package cmd

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	xtopcfg "github.com/ftahirops/xtop/config"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/identity"
	"github.com/ftahirops/xtop/model"
)

// Dracula palette for discover UI (matches ui/styles.go).
var (
	dRed     = lipgloss.Color("#FF5555")
	dGreen   = lipgloss.Color("#50FA7B")
	dCyan    = lipgloss.Color("#8BE9FD")
	dMagenta = lipgloss.Color("#FF79C6")
	dWhite   = lipgloss.Color("#F8F8F2")
	dGray    = lipgloss.Color("#6272A4")
	dYellow  = lipgloss.Color("#F1FA8C")

	dTitle  = lipgloss.NewStyle().Bold(true).Foreground(dCyan)
	dHeader = lipgloss.NewStyle().Bold(true).Foreground(dMagenta)
	dDim    = lipgloss.NewStyle().Foreground(dGray)
	dOK     = lipgloss.NewStyle().Foreground(dGreen)
	dWarn   = lipgloss.NewStyle().Foreground(dYellow)
	dCrit   = lipgloss.NewStyle().Foreground(dRed)
	dVal    = lipgloss.NewStyle().Foreground(dWhite)
)

// discoverDoneMsg is sent when identity.Discover() completes.
type discoverDoneMsg struct {
	id *model.ServerIdentity
}

// serviceItem represents a service in the checkbox list.
type serviceItem struct {
	Name     string
	Version  string
	Ports    []int
	Running  bool
	Critical bool
}

// discoverModel is the Bubbletea model for the discover TUI.
type discoverModel struct {
	step     int // 0=scanning, 1=services, 2=roles, 3=summary
	identity *model.ServerIdentity
	services []serviceItem
	cursor   int
	profile  string
	saved    bool
	err      error
	width    int
	height   int
}

func initialDiscoverModel() discoverModel {
	return discoverModel{step: 0}
}

func (m discoverModel) Init() tea.Cmd {
	return func() tea.Msg {
		id := identity.Discover()
		return discoverDoneMsg{id: id}
	}
}

func (m discoverModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
		switch m.step {
		case 1:
			return m.updateServices(msg)
		case 2:
			return m.updateRoles(msg)
		case 3:
			return m.updateSummary(msg)
		}
	case discoverDoneMsg:
		m.identity = msg.id
		m.services = buildServiceItems(msg.id)
		if len(m.services) > 0 {
			m.step = 1
		} else {
			// No running services found, skip to roles
			m.step = 2
		}
	}
	return m, nil
}

func (m discoverModel) updateServices(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		if m.cursor < len(m.services)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case " ":
		if m.cursor < len(m.services) {
			m.services[m.cursor].Critical = !m.services[m.cursor].Critical
		}
	case "a":
		for i := range m.services {
			m.services[i].Critical = true
		}
	case "n":
		for i := range m.services {
			m.services[i].Critical = false
		}
	case "enter":
		m.step = 2
	}
	return m, nil
}

func (m discoverModel) updateRoles(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "enter" {
		m.profile = engine.SelectProfile(m.identity)
		m.step = 3
		// Save config
		m.err = m.saveConfig()
		m.saved = m.err == nil
	}
	return m, nil
}

func (m discoverModel) updateSummary(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "enter" || msg.String() == "q" {
		return m, tea.Quit
	}
	return m, nil
}

func (m discoverModel) saveConfig() error {
	cfg := xtopcfg.Load()
	cfg.ServerIdentity = m.identity

	var crit []string
	for _, s := range m.services {
		if s.Critical {
			crit = append(crit, s.Name)
		}
	}
	cfg.CriticalServices = crit
	cfg.ThresholdProfile = m.profile

	return xtopcfg.Save(cfg)
}

func (m discoverModel) View() string {
	switch m.step {
	case 0:
		return m.viewScanning()
	case 1:
		return m.viewServices()
	case 2:
		return m.viewRoles()
	case 3:
		return m.viewSummary()
	}
	return ""
}

func (m discoverModel) viewScanning() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(dTitle.Render("  Discovering server identity..."))
	sb.WriteString("\n\n")
	sb.WriteString("  Running 15 probes — please wait...\n")
	return sb.String()
}

func (m discoverModel) viewServices() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(dTitle.Render("  Discovering server identity..."))
	sb.WriteString("\n")
	sb.WriteString(dOK.Render("  [====================] 15/15 probes complete"))
	sb.WriteString("\n\n")

	sb.WriteString(dHeader.Render(fmt.Sprintf("  ── Detected Services (%d found) ", len(m.services))))
	sb.WriteString(dDim.Render(strings.Repeat("─", 40)))
	sb.WriteString("\n")
	sb.WriteString(dDim.Render("  Use j/k to navigate, SPACE to toggle, ENTER to confirm"))
	sb.WriteString("\n\n")

	// Determine visible window
	maxVisible := m.height - 12
	if maxVisible < 5 {
		maxVisible = 5
	}
	startIdx := 0
	if m.cursor >= maxVisible {
		startIdx = m.cursor - maxVisible + 1
	}
	endIdx := startIdx + maxVisible
	if endIdx > len(m.services) {
		endIdx = len(m.services)
	}

	for i := startIdx; i < endIdx; i++ {
		s := m.services[i]
		check := "[ ]"
		if s.Critical {
			check = dOK.Render("[x]")
		}

		name := fmt.Sprintf("%-16s", s.Name)
		ver := fmt.Sprintf("%-10s", s.Version)
		if s.Version == "" {
			ver = fmt.Sprintf("%-10s", "—")
		}

		ports := "—"
		if len(s.Ports) > 0 {
			portStrs := make([]string, len(s.Ports))
			for j, p := range s.Ports {
				portStrs[j] = fmt.Sprintf("%d", p)
			}
			ports = fmt.Sprintf("ports: %-12s", strings.Join(portStrs, ", "))
		}

		status := dOK.Render("running")
		if !s.Running {
			status = dDim.Render("stopped")
		}

		line := fmt.Sprintf("  %s %s %s %s %s", check, name, ver, ports, status)
		if i == m.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.Color("#44475A")).Render(line)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(dDim.Render("  Mark critical services (affects alert sensitivity)"))
	sb.WriteString("\n")
	sb.WriteString(dDim.Render("  a=select all  n=select none  ENTER=confirm"))
	sb.WriteString("\n")
	return sb.String()
}

func (m discoverModel) viewRoles() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(dTitle.Render("  Discovering server identity..."))
	sb.WriteString("\n")
	sb.WriteString(dOK.Render("  [====================] 15/15 probes complete"))
	sb.WriteString("\n\n")

	sb.WriteString(dHeader.Render("  ── Server Roles "))
	sb.WriteString(dDim.Render(strings.Repeat("─", 50)))
	sb.WriteString("\n")
	sb.WriteString(dDim.Render("  Based on 15 evidence probes:"))
	sb.WriteString("\n\n")

	if len(m.identity.RoleScores) == 0 {
		sb.WriteString("  " + dDim.Render("No roles detected with sufficient confidence."))
		sb.WriteString("\n")
	} else {
		for i, rs := range m.identity.RoleScores {
			confStyle := dOK
			if rs.Confidence < 50 {
				confStyle = dWarn
			}

			// Show top 2 evidence items
			var topEvidence string
			shown := rs.Evidence
			if len(shown) > 2 {
				shown = shown[:2]
			}
			topEvidence = strings.Join(shown, ", ")

			sb.WriteString(fmt.Sprintf("   %d. %-20s %s  (%s)\n",
				i+1,
				dVal.Render(string(rs.Role)),
				confStyle.Render(fmt.Sprintf("%d%% confidence", rs.Confidence)),
				dDim.Render(topEvidence),
			))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(dDim.Render("  Press ENTER to continue"))
	sb.WriteString("\n")
	return sb.String()
}

func (m discoverModel) viewSummary() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(dTitle.Render("  Discovering server identity..."))
	sb.WriteString("\n")
	sb.WriteString(dOK.Render("  [====================] 15/15 probes complete"))
	sb.WriteString("\n\n")

	sb.WriteString(dHeader.Render("  ── Tuning Applied "))
	sb.WriteString(dDim.Render(strings.Repeat("─", 48)))
	sb.WriteString("\n\n")

	// Threshold profile
	profileDesc := "default (no profile-specific tuning)"
	if m.profile != "" {
		profileDesc = fmt.Sprintf("%s profile", m.profile)
	}
	sb.WriteString(fmt.Sprintf("   Threshold profile: %s\n", dVal.Render(profileDesc)))

	// Show specific tuning
	if m.profile != "" {
		if p, ok := engine.Profiles[m.profile]; ok {
			tuned := make([]string, 0, len(p))
			for id := range p {
				domain := strings.Split(id, ".")[0]
				tuned = append(tuned, domain)
			}
			// Deduplicate
			seen := map[string]bool{}
			var domains []string
			for _, d := range tuned {
				label := domainLabel(d)
				if !seen[label] {
					seen[label] = true
					domains = append(domains, label)
				}
			}
			for _, d := range domains {
				sb.WriteString(fmt.Sprintf("    %s thresholds: %s\n", d, dOK.Render("tightened")))
			}
		}
	}

	// Critical services
	var critNames []string
	for _, s := range m.services {
		if s.Critical {
			critNames = append(critNames, s.Name)
		}
	}
	if len(critNames) > 0 {
		sb.WriteString(fmt.Sprintf("   Critical services: %s\n", dVal.Render(strings.Join(critNames, ", "))))
	} else {
		sb.WriteString(fmt.Sprintf("   Critical services: %s\n", dDim.Render("none")))
	}

	// Roles
	if len(m.identity.Roles) > 0 {
		roleStrs := make([]string, len(m.identity.Roles))
		for i, r := range m.identity.Roles {
			roleStrs[i] = string(r)
		}
		sb.WriteString(fmt.Sprintf("   Detected roles:    %s\n", dVal.Render(strings.Join(roleStrs, ", "))))
	}

	sb.WriteString("\n")

	// Save status
	if m.saved {
		path := xtopcfg.Path()
		sb.WriteString(dOK.Render(fmt.Sprintf("  Saved to %s", path)))
		sb.WriteString("\n")
		sb.WriteString(dDim.Render("  Run `sudo xtop` to start with tuned configuration."))
		sb.WriteString("\n")
	} else if m.err != nil {
		sb.WriteString(dCrit.Render(fmt.Sprintf("  Error saving config: %v", m.err)))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(dDim.Render("  Press ENTER or q to exit"))
	sb.WriteString("\n")
	return sb.String()
}

// buildServiceItems converts detected services into UI items.
func buildServiceItems(id *model.ServerIdentity) []serviceItem {
	var items []serviceItem
	for _, svc := range id.Services {
		if !svc.Running {
			continue
		}
		items = append(items, serviceItem{
			Name:     svc.Name,
			Version:  svc.Version,
			Ports:    svc.Ports,
			Running:  svc.Running,
			Critical: false,
		})
	}
	return items
}

// domainLabel maps a short domain prefix to a display label.
func domainLabel(prefix string) string {
	switch prefix {
	case "io":
		return "IO"
	case "mem":
		return "Memory"
	case "cpu":
		return "CPU"
	case "net":
		return "Network"
	default:
		if len(prefix) == 0 {
			return prefix
		}
		return strings.ToUpper(prefix[:1]) + prefix[1:]
	}
}

// runDiscover creates and runs the discover TUI.
func runDiscover() error {
	m := initialDiscoverModel()
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
