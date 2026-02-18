package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// Page identifies the current screen.
type Page int

const (
	PageOverview Page = iota
	PageCPU
	PageMemory
	PageIO
	PageNetwork
	PageCgroups
	PageTimeline
	PageEvents
	PageProbe
	pageCount
)

var pageNames = []string{"Overview", "CPU", "Memory", "IO", "Network", "CGroups", "Timeline", "Events", "Probe"}

type tickMsg time.Time

type collectMsg struct {
	snap   *model.Snapshot
	rates  *model.RateSnapshot
	result *model.AnalysisResult
}

// saveConfirmMsg is sent after a save completes.
type saveConfirmMsg struct {
	path string
	err  error
}

// Model is the bubbletea model.
type Model struct {
	engine   *engine.Engine
	interval time.Duration
	width    int
	height   int

	// Data
	snap   *model.Snapshot
	rates  *model.RateSnapshot
	result *model.AnalysisResult

	// Navigation
	page     Page
	showHelp bool
	scroll   int // vertical scroll offset

	// Auto-refresh control
	paused bool

	// Save / status feedback
	saveMsg     string
	saveMsgTime time.Time

	// Cgroup page state
	cgSortCol  cgSort
	cgSelected int

	// Events page state
	eventDetector *engine.EventDetector
	evtSelected   int

	// Overview layout mode
	layoutMode LayoutMode

	// Probe state
	probeManager *engine.ProbeManager
}

// NewModel creates a new TUI model.
func NewModel(eng *engine.Engine, interval time.Duration, dataDir string) Model {
	detector := engine.NewEventDetector()

	// Load daemon events if available
	if dataDir != "" {
		events, err := engine.ReadEventLog(dataDir + "/events.jsonl")
		if err == nil && len(events) > 0 {
			detector.LoadEvents(events)
		}
	}

	// Load default layout from user config
	cfg := loadConfig()
	layout := LayoutMode(cfg.DefaultLayout)
	if layout < 0 || layout >= layoutCount {
		layout = LayoutTwoCol
	}

	return Model{
		engine:        eng,
		interval:      interval,
		eventDetector: detector,
		layoutMode:    layout,
		probeManager:  engine.NewProbeManager(),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(m.interval), collectOnce(m.engine))
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func collectOnce(eng *engine.Engine) tea.Cmd {
	return func() tea.Msg {
		snap, rates, result := eng.Tick()
		return collectMsg{snap: snap, rates: rates, result: result}
	}
}

// saveRCA saves the current analysis state to a JSON file.
func saveRCA(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) tea.Cmd {
	return func() tea.Msg {
		ts := time.Now().Format("20060102-150405")
		path := fmt.Sprintf("xtop-rca-%s.json", ts)

		data := map[string]interface{}{
			"timestamp": time.Now().Format(time.RFC3339),
			"snapshot":  snap,
			"rates":     rates,
			"analysis":  result,
		}

		f, err := os.Create(path)
		if err != nil {
			return saveConfirmMsg{err: err}
		}
		defer f.Close()

		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return saveConfirmMsg{err: err}
		}

		return saveConfirmMsg{path: path}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = true
		case "a":
			m.paused = !m.paused
			if !m.paused {
				// Resume: schedule next tick immediately
				return m, tea.Batch(tick(m.interval), collectOnce(m.engine))
			}
		case "S":
			// Save RCA to file (works on any page)
			if m.snap != nil {
				return m, saveRCA(m.snap, m.rates, m.result)
			}
		case "0":
			m.page = PageOverview
			m.scroll = 0
		case "1":
			m.page = PageCPU
			m.scroll = 0
		case "2":
			m.page = PageMemory
			m.scroll = 0
		case "3":
			m.page = PageIO
			m.scroll = 0
		case "4":
			m.page = PageNetwork
			m.scroll = 0
		case "5":
			m.page = PageCgroups
			m.scroll = 0
		case "6":
			m.page = PageTimeline
			m.scroll = 0
		case "7":
			m.page = PageEvents
			m.scroll = 0
			m.evtSelected = 0
		case "8":
			m.page = PageProbe
			m.scroll = 0
		case "I":
			if m.probeManager.State() != engine.ProbeRunning {
				_ = m.probeManager.Start("auto")
				m.page = PageProbe
				m.scroll = 0
			}
		case "b", "esc":
			m.page = PageOverview
			m.scroll = 0
		case "j", "down":
			if m.page == PageCgroups {
				maxIdx := 0
				if m.snap != nil && len(m.snap.Cgroups) > 0 {
					maxIdx = len(m.snap.Cgroups) - 1
				}
				if m.cgSelected < maxIdx {
					m.cgSelected++
				}
			} else if m.page == PageEvents {
				_, completed := m.eventDetector.AllEvents()
				if m.evtSelected < len(completed)-1 {
					m.evtSelected++
				}
			} else {
				m.scroll++
			}
		case "k", "up":
			if m.page == PageCgroups {
				if m.cgSelected > 0 {
					m.cgSelected--
				}
			} else if m.page == PageEvents {
				if m.evtSelected > 0 {
					m.evtSelected--
				}
			} else if m.scroll > 0 {
				m.scroll--
			}
		case "s":
			if m.page == PageCgroups {
				m.cgSortCol = (m.cgSortCol + 1) % cgSortCount
			}
		case "G":
			m.scroll += 20
		case "g":
			m.scroll = 0
		case "v":
			// Cycle overview layout forward
			m.layoutMode = (m.layoutMode + 1) % layoutCount
		case "V":
			// Cycle overview layout backward
			m.layoutMode = (m.layoutMode - 1 + layoutCount) % layoutCount
		case "f1":
			m.layoutMode = LayoutTwoCol
		case "f2":
			m.layoutMode = LayoutCompact
		case "f3":
			m.layoutMode = LayoutAdaptive
		case "f4":
			m.layoutMode = LayoutGrid
		case "D":
			// Set current layout as default
			if err := saveDefaultLayout(m.layoutMode); err != nil {
				m.saveMsg = fmt.Sprintf("Config error: %v", err)
			} else {
				m.saveMsg = fmt.Sprintf("Default layout set: %s", m.layoutMode)
			}
			m.saveMsgTime = time.Now()
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		if m.paused {
			return m, nil
		}
		return m, tea.Batch(tick(m.interval), collectOnce(m.engine))
	case collectMsg:
		if !m.paused {
			m.snap = msg.snap
			m.rates = msg.rates
			m.result = msg.result
			// Feed event detector
			m.eventDetector.Process(msg.snap, msg.rates, msg.result)
			// Check probe state transitions
			m.probeManager.Tick()
		}
	case saveConfirmMsg:
		if msg.err != nil {
			m.saveMsg = fmt.Sprintf("Save failed: %v", msg.err)
		} else {
			m.saveMsg = fmt.Sprintf("Saved: %s", msg.path)
		}
		m.saveMsgTime = time.Now()
	}
	return m, nil
}

func (m Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}
	if m.width == 0 {
		return "Loading..."
	}
	if m.snap == nil {
		return "Collecting first sample..."
	}

	smartDisks := m.engine.Smart.Get()

	var content string
	switch m.page {
	case PageOverview:
		content = renderOverview(m.snap, m.rates, m.result, m.engine.History, smartDisks, m.probeManager, m.layoutMode, m.width, m.height)
	case PageCPU:
		content = renderCPUPage(m.snap, m.rates, m.result, m.probeManager, m.width, m.height)
	case PageMemory:
		content = renderMemPage(m.snap, m.rates, m.result, m.probeManager, m.width, m.height)
	case PageIO:
		content = renderIOPage(m.snap, m.rates, m.result, smartDisks, m.probeManager, m.width, m.height)
	case PageNetwork:
		content = renderNetPage(m.snap, m.rates, m.result, m.probeManager, m.width, m.height)
	case PageCgroups:
		content = renderCgroupPage(m.snap, m.rates, m.result, m.probeManager, m.cgSortCol, m.cgSelected, m.width, m.height)
	case PageTimeline:
		content = renderTimelinePage(m.engine.History, m.width, m.height)
	case PageEvents:
		active, completed := m.eventDetector.AllEvents()
		content = renderEventsPage(active, completed, m.evtSelected, m.width, m.height)
	case PageProbe:
		content = renderProbePage(m.probeManager, m.width, m.height)
	}

	// Apply scroll
	lines := strings.Split(content, "\n")
	if m.scroll > 0 && m.scroll < len(lines) {
		lines = lines[m.scroll:]
	}
	// Trim to viewport height (leave room for status bar)
	maxLines := m.height - 2
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	content = strings.Join(lines, "\n")

	return content + "\n" + m.renderStatusBar()
}

func (m Model) renderStatusBar() string {
	// Page tabs
	var tabs []string
	for i, name := range pageNames {
		if Page(i) == m.page {
			tabs = append(tabs, headerStyle.Render(fmt.Sprintf("[%d:%s]", i, name)))
		} else {
			tabs = append(tabs, dimStyle.Render(fmt.Sprintf(" %d:%s ", i, name)))
		}
	}
	left := strings.Join(tabs, "")

	// Paused indicator
	if m.paused {
		left += "  " + critStyle.Render("[PAUSED]")
	}

	// Save message (show for 5 seconds)
	if m.saveMsg != "" && time.Since(m.saveMsgTime) < 5*time.Second {
		left += "  " + okStyle.Render(m.saveMsg)
	}

	// Layout indicator on overview
	if m.page == PageOverview {
		left += "  " + dimStyle.Render(fmt.Sprintf("[%s]", m.layoutMode))
	}

	help := helpStyle.Render("I:investigate  v:layout  D:default  a:pause  S:save  ?:help  q:quit")

	gap := m.width - len(stripAnsi(left)) - len(stripAnsi(help))
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + help
}

// stripAnsi is a rough approximation to get display width (strip escape codes).
func stripAnsi(s string) string {
	var out strings.Builder
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func (m Model) renderHelp() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render("xtop — Root-Cause Oriented System Monitor"))
	sb.WriteString("\n\n")
	sb.WriteString(headerStyle.Render("Navigation"))
	sb.WriteString("\n")
	sb.WriteString("  0         Overview (default)\n")
	sb.WriteString("  1         CPU subsystem detail\n")
	sb.WriteString("  2         Memory subsystem (full breakdown)\n")
	sb.WriteString("  3         IO/Disk subsystem (device detail)\n")
	sb.WriteString("  4         Network (packets, connections, sockets)\n")
	sb.WriteString("  5         Cgroups (sortable table)\n")
	sb.WriteString("  6         Timeline (5m history charts)\n")
	sb.WriteString("  7         Events (detected incidents)\n")
	sb.WriteString("  8         Probe investigation (eBPF)\n")
	sb.WriteString("  b / Esc   Back to overview\n")
	sb.WriteString("\n")
	sb.WriteString(headerStyle.Render("Controls"))
	sb.WriteString("\n")
	sb.WriteString("  v/V       Cycle overview layout (F1-F4 for direct)\n")
	sb.WriteString("  D         Set current layout as default\n")
	sb.WriteString("  a         Toggle auto-refresh (pause/resume)\n")
	sb.WriteString("  I         Start eBPF probe investigation (auto-detect)\n")
	sb.WriteString("  S         Save RCA snapshot to JSON file\n")
	sb.WriteString("  j/k       Scroll down/up\n")
	sb.WriteString("  g/G       Top / jump down\n")
	sb.WriteString("  s         Cycle sort column (Cgroups page)\n")
	sb.WriteString("  ?         Toggle this help\n")
	sb.WriteString("  q/Ctrl+C  Quit\n")
	sb.WriteString("\n")
	sb.WriteString(headerStyle.Render("Overview Layouts"))
	sb.WriteString("\n")
	sb.WriteString("  F1 / v    Two-Column (subsystems left, owners+chain right)\n")
	sb.WriteString("  F2        Compact (single summary table)\n")
	sb.WriteString("  F3        Adaptive (healthy=1 line, unhealthy=expanded)\n")
	sb.WriteString("  F4        Grid (2x2 subsystem dashboard)\n")
	sb.WriteString("\n")
	sb.WriteString(headerStyle.Render("Panels"))
	sb.WriteString("\n")
	sb.WriteString("  Overview   Health + PSI + capacity + owners + chain + RCA\n")
	sb.WriteString("  CPU        Busy/steal/softirq + throttling + top cgroups/PIDs\n")
	sb.WriteString("  Memory     Full breakdown + swap + vmstat + reclaim + top consumers\n")
	sb.WriteString("  IO         Per-device stats + IO type + D-state + top cgroups/PIDs\n")
	sb.WriteString("  Network    Health + throughput + connections + top consumers\n")
	sb.WriteString("  CGroups    All cgroups sortable by CPU/throttle/mem/oom/IO\n")
	sb.WriteString("  Timeline   5m history charts for PSI/load/D-state\n")
	sb.WriteString("  Events     Detected incidents with RCA detail\n")
	sb.WriteString("  Probe      eBPF investigation (off-CPU/IO latency/locks/retrans)\n")
	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("Press any key to close"))
	return sb.String()
}
