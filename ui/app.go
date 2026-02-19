package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
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
	PageThresholds
	PageDiskGuard
	pageCount
)

var pageNames = []string{"Overview", "CPU", "Memory", "IO", "Network", "CGroups", "Timeline", "Events", "Probe", "Thresholds", "DiskGuard"}

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

// frozenProc tracks a process frozen by Contain mode.
type frozenProc struct {
	Comm      string
	WritePath string
	FrozenAt  time.Time
	StartTime string // /proc/PID/stat field 22 — unique per PID lifecycle
}

// readProcStartTime reads field 22 (starttime) from /proc/PID/stat.
// Returns empty string on error. Used to detect PID reuse.
func readProcStartTime(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	content := string(data)
	closeIdx := strings.LastIndex(content, ")")
	if closeIdx < 0 || closeIdx+2 >= len(content) {
		return ""
	}
	fields := strings.Fields(content[closeIdx+2:])
	if len(fields) < 20 {
		return ""
	}
	return fields[19] // field 22 = starttime (0-indexed after comm: index 19)
}

// verifyFrozenPID checks that a frozen PID still belongs to the same process.
func verifyFrozenPID(pid int, fp frozenProc) bool {
	st := readProcStartTime(pid)
	return st != "" && st == fp.StartTime
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

	// DiskGuard mode
	diskGuardMode  string
	diskGuardMsg   string    // action feedback message
	diskGuardMsgT  time.Time // when message was set
	frozenPIDs     map[int]frozenProc // PIDs frozen by Contain mode
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
		diskGuardMode: "Monitor",
		frozenPIDs:    make(map[int]frozenProc),
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
		case "9":
			m.page = PageThresholds
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
		case "enter":
			// Culprit jump: from overview or events, go to bottleneck detail page
			if m.page == PageOverview && m.result != nil && m.result.PrimaryBottleneck != "" {
				m.page = bottleneckToPage(m.result.PrimaryBottleneck)
				m.scroll = 0
			} else if m.page == PageEvents {
				_, completed := m.eventDetector.AllEvents()
				if m.evtSelected < len(completed) {
					evt := completed[m.evtSelected]
					m.page = bottleneckToPage(evt.Bottleneck)
					m.scroll = 0
				}
			}
		case "E":
			// Export incident report as markdown
			active, completed := m.eventDetector.AllEvents()
			return m, exportIncidentMarkdown(m.snap, m.rates, m.result, active, completed)
		case "D":
			m.page = PageDiskGuard
			m.scroll = 0
		case "ctrl+d":
			// Set current layout as default
			if err := saveDefaultLayout(m.layoutMode); err != nil {
				m.saveMsg = fmt.Sprintf("Config error: %v", err)
			} else {
				m.saveMsg = fmt.Sprintf("Default layout set: %s", m.layoutMode)
			}
			m.saveMsgTime = time.Now()
		case "m", "M":
			// Cycle DiskGuard mode (only on DiskGuard page)
			if m.page == PageDiskGuard {
				switch m.diskGuardMode {
				case "Monitor":
					m.diskGuardMode = "Contain"
				case "Contain":
					m.diskGuardMode = "Action"
				default:
					m.diskGuardMode = "Monitor"
				}
			}
		case "x", "X":
			// Action mode: kill top writer (only on DiskGuard page in Action mode)
			if m.page == PageDiskGuard && m.diskGuardMode == "Action" && m.rates != nil {
				procs := make([]model.ProcessRate, len(m.rates.ProcessRates))
				copy(procs, m.rates.ProcessRates)
				sort.Slice(procs, func(i, j int) bool {
					return procs[i].WriteMBs > procs[j].WriteMBs
				})
				if len(procs) > 0 && procs[0].WriteMBs > 0.1 {
					pid := procs[0].PID
					comm := procs[0].Comm
					wp := procs[0].WritePath
					// Verify PID identity before killing
					st := readProcStartTime(pid)
					if st == "" {
						m.diskGuardMsg = fmt.Sprintf("PID %d no longer exists", pid)
					} else {
						err := syscall.Kill(pid, syscall.SIGKILL)
						if err != nil {
							m.diskGuardMsg = fmt.Sprintf("Failed to kill PID %d (%s): %v", pid, comm, err)
						} else {
							if wp != "" {
								m.diskGuardMsg = fmt.Sprintf("KILLED PID %d (%s) — was writing to %s", pid, comm, wp)
							} else {
								m.diskGuardMsg = fmt.Sprintf("KILLED PID %d (%s)", pid, comm)
							}
						}
					}
					delete(m.frozenPIDs, pid)
					m.diskGuardMsgT = time.Now()
				} else {
					m.diskGuardMsg = "No active writer to kill"
					m.diskGuardMsgT = time.Now()
				}
			}
		case "f", "F":
			// Contain/Action mode: manually freeze top writer
			if m.page == PageDiskGuard && (m.diskGuardMode == "Contain" || m.diskGuardMode == "Action") && m.rates != nil {
				procs := make([]model.ProcessRate, len(m.rates.ProcessRates))
				copy(procs, m.rates.ProcessRates)
				sort.Slice(procs, func(i, j int) bool {
					return procs[i].WriteMBs > procs[j].WriteMBs
				})
				if len(procs) > 0 && procs[0].WriteMBs > 0.1 {
					pid := procs[0].PID
					if _, already := m.frozenPIDs[pid]; already {
						m.diskGuardMsg = fmt.Sprintf("PID %d (%s) already frozen", pid, procs[0].Comm)
					} else {
						st := readProcStartTime(pid)
						err := syscall.Kill(pid, syscall.SIGSTOP)
						if err != nil {
							m.diskGuardMsg = fmt.Sprintf("Failed to freeze PID %d: %v", pid, err)
						} else {
							m.frozenPIDs[pid] = frozenProc{
								Comm:      procs[0].Comm,
								WritePath: procs[0].WritePath,
								FrozenAt:  time.Now(),
								StartTime: st,
							}
							m.diskGuardMsg = fmt.Sprintf("FROZEN PID %d (%s) — writing paused", pid, procs[0].Comm)
						}
					}
					m.diskGuardMsgT = time.Now()
				}
			}
		case "r", "R":
			// Resume all frozen processes (verify PID identity first)
			if m.page == PageDiskGuard && len(m.frozenPIDs) > 0 {
				resumed := 0
				for pid, fp := range m.frozenPIDs {
					if verifyFrozenPID(pid, fp) {
						if err := syscall.Kill(pid, syscall.SIGCONT); err == nil {
							resumed++
						}
					}
					delete(m.frozenPIDs, pid)
				}
				m.diskGuardMsg = fmt.Sprintf("RESUMED %d frozen process(es)", resumed)
				m.diskGuardMsgT = time.Now()
			}
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
			// DiskGuard Contain mode: auto-freeze top writers when CRIT
			m.diskGuardContain()
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
	case PageThresholds:
		content = renderThresholdsPage(m.snap, m.rates, m.result, m.width, m.height)
	case PageDiskGuard:
		dgMsg := ""
		if time.Since(m.diskGuardMsgT) < 10*time.Second {
			dgMsg = m.diskGuardMsg
		}
		content = renderDiskGuardPage(m.snap, m.rates, m.result, m.probeManager, m.diskGuardMode, dgMsg, m.frozenPIDs, m.width, m.height)
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
		label := fmt.Sprintf("%d:%s", i, name)
		if Page(i) == PageDiskGuard {
			label = "D:" + name
		}
		if Page(i) == m.page {
			tabs = append(tabs, headerStyle.Render("["+label+"]"))
		} else {
			tabs = append(tabs, dimStyle.Render(" "+label+" "))
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

	help := helpStyle.Render("D:disk  I:investigate  E:export  v:layout  a:pause  S:save  ?:help  q:quit")

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

// bottleneckToPage maps a bottleneck name to its detail page.
func bottleneckToPage(bneck string) Page {
	switch {
	case strings.Contains(bneck, "CPU"):
		return PageCPU
	case strings.Contains(bneck, "Memory"):
		return PageMemory
	case strings.Contains(bneck, "Filesystem"), strings.Contains(bneck, "Disk Space"):
		return PageDiskGuard
	case strings.Contains(bneck, "IO"), strings.Contains(bneck, "Disk"):
		return PageIO
	case strings.Contains(bneck, "Network"), strings.Contains(bneck, "Net"):
		return PageNetwork
	default:
		return PageOverview
	}
}

// exportIncidentMarkdown generates a markdown report for the current state.
func exportIncidentMarkdown(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	active *model.Event, completed []model.Event) tea.Cmd {
	return func() tea.Msg {
		ts := time.Now().Format("20060102-150405")
		path := fmt.Sprintf("xtop-incident-%s.md", ts)

		var sb strings.Builder
		sb.WriteString("# xtop Incident Report\n\n")
		sb.WriteString(fmt.Sprintf("**Generated**: %s\n\n", time.Now().Format(time.RFC3339)))

		if result != nil {
			sb.WriteString("## System Health\n\n")
			sb.WriteString(fmt.Sprintf("- **Health**: %s\n", result.Health))
			sb.WriteString(fmt.Sprintf("- **Primary Bottleneck**: %s (score %d%%)\n", result.PrimaryBottleneck, result.PrimaryScore))
			sb.WriteString(fmt.Sprintf("- **Confidence**: %d%%\n", result.Confidence))
			if result.PrimaryProcess != "" {
				sb.WriteString(fmt.Sprintf("- **Culprit Process**: %s (PID %d)\n", result.PrimaryProcess, result.PrimaryPID))
			}
			if result.PrimaryCulprit != "" {
				sb.WriteString(fmt.Sprintf("- **Culprit Cgroup**: %s\n", result.PrimaryCulprit))
			}
			if result.CausalChain != "" {
				sb.WriteString(fmt.Sprintf("- **Causal Chain**: %s\n", result.CausalChain))
			}
			sb.WriteString("\n")

			if len(result.TopChanges) > 0 {
				sb.WriteString("## What Changed (last 30s)\n\n")
				sb.WriteString("| Metric | Change | Current |\n")
				sb.WriteString("|--------|--------|--------|\n")
				for _, c := range result.TopChanges {
					arrow := "↓"
					sign := ""
					if c.Rising {
						arrow = "↑"
						sign = "+"
					}
					sb.WriteString(fmt.Sprintf("| %s %s | %s%.0f%% | %s |\n",
						arrow, c.Name, sign, c.DeltaPct, c.Current))
				}
				sb.WriteString("\n")
			}

			if len(result.PrimaryEvidence) > 0 {
				sb.WriteString("## Evidence\n\n")
				for _, e := range result.PrimaryEvidence {
					sb.WriteString(fmt.Sprintf("- %s\n", e))
				}
				sb.WriteString("\n")
			}

			if len(result.Actions) > 0 {
				sb.WriteString("## Suggested Actions\n\n")
				for i, a := range result.Actions {
					sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, a.Summary))
					if a.Command != "" {
						sb.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", a.Command))
					}
				}
				sb.WriteString("\n")
			}

			if len(result.Exhaustions) > 0 {
				sb.WriteString("## Exhaustion Predictions\n\n")
				for _, ex := range result.Exhaustions {
					sb.WriteString(fmt.Sprintf("- **%s**: %.0f%% used, exhaustion in ~%.0f min\n",
						ex.Resource, ex.CurrentPct, ex.EstMinutes))
				}
				sb.WriteString("\n")
			}

			if len(result.Degradations) > 0 {
				sb.WriteString("## Slow Degradation Trends\n\n")
				for _, d := range result.Degradations {
					sb.WriteString(fmt.Sprintf("- **%s** %s at %.2f %s\n",
						d.Metric, d.Direction, d.Rate, d.Unit))
				}
				sb.WriteString("\n")
			}
		}

		// Active incident
		if active != nil {
			sb.WriteString("## Active Incident\n\n")
			sb.WriteString(fmt.Sprintf("- **Start**: %s\n", active.StartTime.Format(time.RFC3339)))
			sb.WriteString(fmt.Sprintf("- **Bottleneck**: %s (peak score %d%%)\n", active.Bottleneck, active.PeakScore))
			if active.CulpritProcess != "" {
				sb.WriteString(fmt.Sprintf("- **Culprit**: %s (PID %d)\n", active.CulpritProcess, active.CulpritPID))
			}
			if len(active.Timeline) > 0 {
				sb.WriteString("\n### Timeline\n\n")
				sb.WriteString("| Time | Event |\n")
				sb.WriteString("|------|-------|\n")
				for _, te := range active.Timeline {
					sb.WriteString(fmt.Sprintf("| %s | %s |\n", te.Time.Format("15:04:05"), te.Message))
				}
			}
			sb.WriteString("\n")
		}

		// Recent completed events
		if len(completed) > 0 {
			sb.WriteString("## Recent Events\n\n")
			sb.WriteString("| Time | Duration | Health | Bottleneck | Score | Culprit |\n")
			sb.WriteString("|------|----------|--------|------------|-------|--------|\n")
			shown := completed
			if len(shown) > 10 {
				shown = shown[:10]
			}
			for _, evt := range shown {
				dur := fmt.Sprintf("%ds", evt.Duration)
				if evt.Duration >= 60 {
					dur = fmt.Sprintf("%dm%ds", evt.Duration/60, evt.Duration%60)
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d%% | %s |\n",
					evt.StartTime.Format("15:04:05"), dur, evt.PeakHealth,
					evt.Bottleneck, evt.PeakScore, evt.CulpritProcess))
			}
			sb.WriteString("\n")
		}

		sb.WriteString("---\n*Generated by xtop*\n")

		if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
			return saveConfirmMsg{err: err}
		}
		return saveConfirmMsg{path: path}
	}
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
	sb.WriteString("  9         Thresholds & limits reference\n")
	sb.WriteString("  b / Esc   Back to overview\n")
	sb.WriteString("\n")
	sb.WriteString(headerStyle.Render("Controls"))
	sb.WriteString("\n")
	sb.WriteString("  v/V       Cycle overview layout (F1-F4 for direct)\n")
	sb.WriteString("  D         DiskGuard page (filesystem space monitor)\n")
	sb.WriteString("  Ctrl+D    Set current layout as default\n")
	sb.WriteString("  a         Toggle auto-refresh (pause/resume)\n")
	sb.WriteString("  I         Start eBPF probe investigation (auto-detect)\n")
	sb.WriteString("  S         Save RCA snapshot to JSON file\n")
	sb.WriteString("  E         Export incident report as markdown\n")
	sb.WriteString("  Enter     Jump to bottleneck detail page\n")
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
	sb.WriteString("  Thresholds All metrics with thresholds, limits, and scoring rules\n")
	sb.WriteString("  DiskGuard  Filesystem monitor: growth, ETA, big files, writers\n")
	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("Press any key to close"))
	return sb.String()
}

// diskGuardContain handles automatic freeze/resume in Contain mode.
func (m *Model) diskGuardContain() {
	if m.result == nil || m.rates == nil {
		return
	}

	worst := m.result.DiskGuardWorst

	// Contain mode: auto-freeze top writers when CRIT
	if m.diskGuardMode == "Contain" && worst == "CRIT" {
		procs := make([]model.ProcessRate, len(m.rates.ProcessRates))
		copy(procs, m.rates.ProcessRates)
		sort.Slice(procs, func(i, j int) bool {
			return procs[i].WriteMBs > procs[j].WriteMBs
		})

		for _, p := range procs {
			if p.WriteMBs < 0.5 {
				break
			}
			if _, already := m.frozenPIDs[p.PID]; already {
				continue
			}
			st := readProcStartTime(p.PID)
			err := syscall.Kill(p.PID, syscall.SIGSTOP)
			if err == nil {
				m.frozenPIDs[p.PID] = frozenProc{
					Comm:      p.Comm,
					WritePath: p.WritePath,
					FrozenAt:  time.Now(),
					StartTime: st,
				}
				m.diskGuardMsg = fmt.Sprintf("AUTO-FROZEN PID %d (%s) — disk CRIT, writing paused", p.PID, p.Comm)
				m.diskGuardMsgT = time.Now()
			}
		}
	}

	// Auto-resume when disk drops to OK (any mode) — verify PID identity
	if worst == "OK" && len(m.frozenPIDs) > 0 {
		resumed := 0
		for pid, fp := range m.frozenPIDs {
			if verifyFrozenPID(pid, fp) {
				if err := syscall.Kill(pid, syscall.SIGCONT); err == nil {
					resumed++
				}
			}
			delete(m.frozenPIDs, pid)
		}
		if resumed > 0 {
			m.diskGuardMsg = fmt.Sprintf("AUTO-RESUMED %d process(es) — disk OK", resumed)
			m.diskGuardMsgT = time.Now()
		}
	}

	// Clean up dead or reused PIDs from frozen map
	for pid, fp := range m.frozenPIDs {
		if !verifyFrozenPID(pid, fp) {
			delete(m.frozenPIDs, pid)
		}
	}
}
