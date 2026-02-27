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
	"github.com/charmbracelet/lipgloss"
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
	PageSecurity
	PageLogs
	PageServices
	PageDiag
	pageCount
)

var pageNames = []string{"Overview", "CPU", "Memory", "IO", "Network", "CGroups", "Timeline", "Events", "Probe", "Thresholds", "DiskGuard", "Security", "Logs", "Services", "Diagnostics"}

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

// freezeDenylist prevents critical system processes from being frozen or killed.
var freezeDenylist = map[string]bool{
	"mysqld": true, "mariadbd": true, "postgres": true, "mongod": true,
	"redis-server": true, "journald": true, "systemd": true,
	"systemd-journald": true, "sshd": true, "kubelet": true,
	"containerd": true, "dockerd": true, "crio": true, "xtop": true,
}

// Model is the bubbletea model.
type Model struct {
	ticker   engine.Ticker
	engine   *engine.Engine
	interval time.Duration
	width    int
	height   int

	// Data
	snap   *model.Snapshot
	rates  *model.RateSnapshot
	result *model.AnalysisResult

	// Navigation
	page        Page
	showHelp    bool
	showExplain bool
	scroll      int // vertical scroll offset

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

	// Server identity roles (loaded from config)
	serverRoles []string

	// DiskGuard mode
	diskGuardMode       string
	diskGuardMsg        string             // action feedback message
	diskGuardMsgT       time.Time          // when message was set
	frozenPIDs          map[int]frozenProc // PIDs frozen by Contain mode
	lastActionTime      time.Time          // cooldown: last auto-action time
	incidentActionCount int                // max actions per incident
	stableStart         time.Time          // tracks when disk became stable OK

	// Beginner mode / onboarding
	showOnboarding bool // true when ExperienceLevel == "" (first run)
	beginnerMode   bool // true when level is "beginner"

	// Explain side panel
	explainPanelOpen bool // 'E' toggles side panel
	explainScroll    int  // scroll offset within explain panel
	explainFocused   bool // Tab toggles focus to panel for scrolling
}

// NewModel creates a new TUI model.
func NewModel(ticker engine.Ticker, interval time.Duration, dataDir string) Model {
	detector := engine.NewEventDetector()

	// Load daemon events if available
	if dataDir != "" {
		events, err := engine.ReadEventLog(dataDir + "/events.jsonl")
		if err == nil && len(events) > 0 {
			detector.LoadEvents(events)
		}
	}

	// Load default layout and roles from user config
	cfg := loadConfig()
	layout := LayoutMode(cfg.DefaultLayout)
	if layout < 0 || layout >= layoutCount {
		layout = LayoutTwoCol
	}
	roles := cfg.Roles

	// Determine beginner/onboarding state
	showOnboarding := cfg.ExperienceLevel == ""
	beginnerMode := cfg.ExperienceLevel == "beginner"

	base := ticker.Base()
	return Model{
		ticker:         ticker,
		engine:         base,
		interval:       interval,
		eventDetector:  detector,
		layoutMode:     layout,
		serverRoles:    roles,
		probeManager:   engine.NewProbeManager(),
		diskGuardMode:  "Monitor",
		frozenPIDs:     make(map[int]frozenProc),
		showOnboarding: showOnboarding,
		beginnerMode:   beginnerMode,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(m.interval), collectOnce(m.ticker))
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func collectOnce(ticker engine.Ticker) tea.Cmd {
	return func() tea.Msg {
		snap, rates, result := ticker.Tick()
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

		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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
		// Onboarding: only accept 1, 2, or quit
		if m.showOnboarding {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "1":
				m.showOnboarding = false
				m.beginnerMode = true
				_ = saveExperienceLevel("beginner")
			case "2":
				m.showOnboarding = false
				m.beginnerMode = false
				_ = saveExperienceLevel("advanced")
			}
			return m, nil
		}
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		// Explain panel focused: capture scroll keys
		if m.explainPanelOpen && m.explainFocused {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "j", "down":
				m.explainScroll++ // clamped in renderExplainSidePanel
				if m.explainScroll > 200 {
					m.explainScroll = 200 // safety cap
				}
				return m, nil
			case "k", "up":
				if m.explainScroll > 0 {
					m.explainScroll--
				}
				return m, nil
			case "tab":
				m.explainFocused = false
				return m, nil
			case "E":
				m.explainPanelOpen = false
				m.explainFocused = false
				m.explainScroll = 0
				return m, nil
			}
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
				return m, tea.Batch(tick(m.interval), collectOnce(m.ticker))
			}
		case "n":
			// Step one frame when paused in replay mode
			if m.paused {
				if p, ok := m.ticker.(*engine.Player); ok {
					snap, rates, result := p.Tick()
					if snap != nil {
						m.snap = snap
						m.rates = rates
						m.result = result
						m.eventDetector.Process(snap, rates, result)
					}
				}
			}
		case "[":
			if p, ok := m.ticker.(*engine.Player); ok {
				target := p.Index() - 10
				snap, rates, result := p.Seek(target)
				if snap != nil {
					m.snap = snap
					m.rates = rates
					m.result = result
					m.eventDetector.Process(snap, rates, result)
				}
			}
		case "]":
			if p, ok := m.ticker.(*engine.Player); ok {
				target := p.Index() + 10
				snap, rates, result := p.Seek(target)
				if snap != nil {
					m.snap = snap
					m.rates = rates
					m.result = result
					m.eventDetector.Process(snap, rates, result)
				}
			}
		case "{":
			if p, ok := m.ticker.(*engine.Player); ok {
				target := p.Index() - 60
				snap, rates, result := p.Seek(target)
				if snap != nil {
					m.snap = snap
					m.rates = rates
					m.result = result
					m.eventDetector.Process(snap, rates, result)
				}
			}
		case "}":
			if p, ok := m.ticker.(*engine.Player); ok {
				target := p.Index() + 60
				snap, rates, result := p.Seek(target)
				if snap != nil {
					m.snap = snap
					m.rates = rates
					m.result = result
					m.eventDetector.Process(snap, rates, result)
				}
			}
		case "J":
			if p, ok := m.ticker.(*engine.Player); ok {
				snap, rates, result := p.Seek(0)
				if snap != nil {
					m.snap = snap
					m.rates = rates
					m.result = result
					m.eventDetector.Process(snap, rates, result)
				}
			}
		case "K":
			if p, ok := m.ticker.(*engine.Player); ok {
				snap, rates, result := p.Seek(p.Len() - 1)
				if snap != nil {
					m.snap = snap
					m.rates = rates
					m.result = result
					m.eventDetector.Process(snap, rates, result)
				}
			}
		case "S":
			// Save RCA to file (works on any page)
			if m.snap != nil {
				return m, saveRCA(m.snap, m.rates, m.result)
			}
		case "0":
			m.page = PageOverview
			m.scroll = 0
			m.explainScroll = 0
		case "1":
			m.page = PageCPU
			m.scroll = 0
			m.explainScroll = 0
		case "2":
			m.page = PageMemory
			m.scroll = 0
			m.explainScroll = 0
		case "3":
			m.page = PageIO
			m.scroll = 0
			m.explainScroll = 0
		case "4":
			m.page = PageNetwork
			m.scroll = 0
			m.explainScroll = 0
		case "5":
			m.page = PageCgroups
			m.scroll = 0
			m.explainScroll = 0
		case "6":
			m.page = PageTimeline
			m.scroll = 0
			m.explainScroll = 0
		case "7":
			m.page = PageEvents
			m.scroll = 0
			m.explainScroll = 0
			m.evtSelected = 0
		case "8":
			m.page = PageProbe
			m.scroll = 0
			m.explainScroll = 0
		case "9":
			m.page = PageThresholds
			m.scroll = 0
			m.explainScroll = 0
		case "I":
			if m.probeManager.State() != engine.ProbeRunning {
				_ = m.probeManager.Start("auto")
				m.page = PageProbe
				m.scroll = 0
				m.explainScroll = 0
			}
		case "b", "esc":
			m.page = PageOverview
			m.scroll = 0
			m.explainScroll = 0
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
		case "f5":
			m.layoutMode = LayoutHtop
		case "f6":
			m.layoutMode = LayoutBtop
		case "enter":
			// Culprit jump: from overview or events, go to bottleneck detail page
			if m.page == PageOverview && m.result != nil && m.result.PrimaryBottleneck != "" {
				m.page = bottleneckToPage(m.result.PrimaryBottleneck)
				m.scroll = 0
				m.explainScroll = 0
			} else if m.page == PageEvents {
				_, completed := m.eventDetector.AllEvents()
				if m.evtSelected < len(completed) {
					evt := completed[m.evtSelected]
					m.page = bottleneckToPage(evt.Bottleneck)
					m.scroll = 0
					m.explainScroll = 0
				}
			}
		case "E":
			// Toggle explain side panel
			m.explainPanelOpen = !m.explainPanelOpen
			if !m.explainPanelOpen {
				m.explainFocused = false
				m.explainScroll = 0
			}
		case "tab":
			// Focus/unfocus explain panel for scrolling
			if m.explainPanelOpen {
				m.explainFocused = !m.explainFocused
			}
		case "P":
			// Export incident report as markdown (was E, moved for explain panel)
			active, completed := m.eventDetector.AllEvents()
			return m, exportIncidentMarkdown(m.snap, m.rates, m.result, active, completed)
		case "D":
			m.page = PageDiskGuard
			m.scroll = 0
			m.explainScroll = 0
		case "L":
			m.page = PageSecurity
			m.scroll = 0
			m.explainScroll = 0
		case "O":
			m.page = PageLogs
			m.scroll = 0
			m.explainScroll = 0
		case "H":
			m.page = PageServices
			m.scroll = 0
			m.explainScroll = 0
		case "W":
			m.page = PageDiag
			m.scroll = 0
			m.explainScroll = 0
		case "ctrl+d":
			// Set current layout as default
			if err := saveDefaultLayout(m.layoutMode); err != nil {
				m.saveMsg = fmt.Sprintf("Error: %v", err)
			} else {
				m.saveMsg = fmt.Sprintf("Default layout: %s", m.layoutMode)
			}
			m.saveMsgTime = time.Now()
		case "e":
			// Toggle explain verdict panel
			if m.result != nil {
				m.showExplain = !m.showExplain
			}
		case "A":
			// Switch to advanced mode (from beginner)
			if m.beginnerMode {
				m.beginnerMode = false
				_ = saveExperienceLevel("advanced")
				m.saveMsg = "Switched to Advanced mode"
				m.saveMsgTime = time.Now()
			}
		case "B":
			// Switch to beginner mode (from advanced)
			if !m.beginnerMode {
				m.beginnerMode = true
				_ = saveExperienceLevel("beginner")
				m.saveMsg = "Switched to Simple mode"
				m.saveMsgTime = time.Now()
			}
		case "m", "M":
			// Cycle DiskGuard mode (only on DiskGuard page)
			if m.page == PageDiskGuard {
				switch m.diskGuardMode {
				case "Monitor":
					m.diskGuardMode = "DryRun"
				case "DryRun":
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
					if freezeDenylist[comm] {
						m.diskGuardMsg = fmt.Sprintf("Skipped: PID %d (%s) is in denylist", pid, comm)
					} else {
						// #11: Verify PID identity before killing — store and re-check
						st := readProcStartTime(pid)
						if st == "" {
							m.diskGuardMsg = fmt.Sprintf("PID %d no longer exists", pid)
						} else if st2 := readProcStartTime(pid); st2 != st {
							m.diskGuardMsg = fmt.Sprintf("PID %d was reused, aborting kill", pid)
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
					}
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
					comm := procs[0].Comm
					if freezeDenylist[comm] {
						m.diskGuardMsg = fmt.Sprintf("Skipped: PID %d (%s) is in denylist", pid, comm)
					} else if _, already := m.frozenPIDs[pid]; already {
						m.diskGuardMsg = fmt.Sprintf("PID %d (%s) already frozen", pid, comm)
					} else {
						// #11: Verify PID still exists before sending SIGSTOP
						st := readProcStartTime(pid)
						if st == "" {
							m.diskGuardMsg = fmt.Sprintf("PID %d no longer exists", pid)
							m.diskGuardMsgT = time.Now()
							break
						}
						err := syscall.Kill(pid, syscall.SIGSTOP)
						if err != nil {
							m.diskGuardMsg = fmt.Sprintf("Failed to freeze PID %d: %v", pid, err)
						} else {
							m.frozenPIDs[pid] = frozenProc{
								Comm:      comm,
								WritePath: procs[0].WritePath,
								FrozenAt:  time.Now(),
								StartTime: st,
							}
							m.diskGuardMsg = fmt.Sprintf("FROZEN PID %d (%s) — writing paused", pid, comm)
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
		return m, tea.Batch(tick(m.interval), collectOnce(m.ticker))
	case collectMsg:
		if !m.paused {
			m.snap = msg.snap
			m.rates = msg.rates
			m.result = msg.result
			// Feed event detector
			m.eventDetector.Process(msg.snap, msg.rates, msg.result)
			// Check probe state transitions
			m.probeManager.Tick()
			// Watchdog auto-trigger: start domain probes when RCA fires
			if msg.result != nil && msg.result.Watchdog.Active {
				if m.probeManager.State() != engine.ProbeRunning {
					_ = m.probeManager.StartDomain(msg.result.Watchdog.Domain)
				}
			}
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
	if m.showOnboarding {
		if m.width == 0 {
			return "Loading..."
		}
		return renderOnboarding(m.width, m.height)
	}
	if m.showHelp {
		return m.renderHelp()
	}
	if m.width == 0 {
		return "Loading..."
	}
	if m.snap == nil {
		return "Collecting first sample..."
	}

	// Determine rendering width (narrower when explain panel is open)
	renderW := m.width
	var explainW int
	if m.explainPanelOpen {
		renderW = m.width * 65 / 100
		explainW = m.width - renderW - 1
		if explainW < 20 {
			explainW = 20
			renderW = m.width - explainW - 1
		}
		if renderW < 40 {
			// Terminal too narrow for side panel — disable it
			renderW = m.width
			explainW = 0
		}
	}

	smartDisks := m.engine.Smart.Get()

	var content string
	// Beginner mode: render simplified page on overview
	if m.beginnerMode && m.page == PageOverview {
		content = renderBeginnerPage(m.snap, m.rates, m.result, renderW, m.height)
	} else {
		switch m.page {
		case PageOverview:
			content = renderOverview(m.snap, m.rates, m.result, m.engine.History, smartDisks, m.probeManager, m.layoutMode, renderW, m.height)
		case PageCPU:
			content = renderCPUPage(m.snap, m.rates, m.result, m.probeManager, renderW, m.height)
		case PageMemory:
			content = renderMemPage(m.snap, m.rates, m.result, m.probeManager, renderW, m.height)
		case PageIO:
			content = renderIOPage(m.snap, m.rates, m.result, smartDisks, m.probeManager, renderW, m.height)
		case PageNetwork:
			content = renderNetPage(m.snap, m.rates, m.result, m.probeManager, renderW, m.height)
		case PageCgroups:
			content = renderCgroupPage(m.snap, m.rates, m.result, m.probeManager, m.cgSortCol, m.cgSelected, renderW, m.height)
		case PageTimeline:
			content = renderTimelinePage(m.engine.History, renderW, m.height)
		case PageEvents:
			active, completed := m.eventDetector.AllEvents()
			content = renderEventsPage(active, completed, m.evtSelected, renderW, m.height)
		case PageProbe:
			content = renderProbePage(m.probeManager, m.snap, renderW, m.height)
		case PageThresholds:
			content = renderThresholdsPage(m.snap, m.rates, m.result, renderW, m.height)
		case PageDiskGuard:
			dgMsg := ""
			if time.Since(m.diskGuardMsgT) < 10*time.Second {
				dgMsg = m.diskGuardMsg
			}
			content = renderDiskGuardPage(m.snap, m.rates, m.result, m.probeManager, m.diskGuardMode, dgMsg, m.frozenPIDs, renderW, m.height)
		case PageSecurity:
			content = renderSecurityPage(m.snap, m.rates, m.result, m.probeManager, renderW, m.height)
		case PageLogs:
			content = renderLogsPage(m.snap, m.rates, m.result, m.probeManager, renderW, m.height)
		case PageServices:
			content = renderServicesPage(m.snap, m.rates, m.result, m.probeManager, renderW, m.height)
		case PageDiag:
			content = renderDiagPage(m.snap, m.rates, m.result, m.probeManager, renderW, m.height)
		}
	}

	// Old explain verdict panel (appended after page content when 'e' is pressed)
	if m.showExplain && m.result != nil {
		content += renderExplainPanel(m.result, renderW)
	}

	// Explain side panel (joined as right column when 'E' is pressed)
	if m.explainPanelOpen && explainW > 0 {
		panel := renderExplainSidePanel(m.page, m.result, explainW, m.height, m.explainScroll, m.explainFocused)
		content = joinColumns(content, panel, renderW, "")
	}

	// Inject clock + interval into the first line (top-right)
	content = m.injectClock(content)

	// Apply scroll (#34: clamp scroll to valid range)
	lines := strings.Split(content, "\n")
	if m.scroll >= len(lines) {
		m.scroll = len(lines) - 1
	}
	if m.scroll < 0 {
		m.scroll = 0
	}
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
	// Page keys
	pageKey := func(i int) string {
		switch Page(i) {
		case PageDiskGuard:
			return "D"
		case PageSecurity:
			return "L"
		case PageLogs:
			return "O"
		case PageServices:
			return "H"
		case PageDiag:
			return "W"
		default:
			return fmt.Sprintf("%d", i)
		}
	}

	// Full and abbreviated page labels
	type pageLabel struct {
		full  string
		short string
		tiny  string // key only
	}
	labels := make([]pageLabel, len(pageNames))
	for i, name := range pageNames {
		key := pageKey(i)
		labels[i] = pageLabel{
			full:  key + ":" + name,
			short: key + ":" + shortPageName(name),
			tiny:  key,
		}
	}

	// Build tabs at a given label tier: 0=full, 1=short, 2=tiny
	buildTabs := func(tier int) string {
		var tabs []string
		for i, lbl := range labels {
			var label string
			switch tier {
			case 0:
				label = lbl.full
			case 1:
				label = lbl.short
			default:
				label = lbl.tiny
			}
			if Page(i) == m.page {
				tabs = append(tabs, headerStyle.Render("["+label+"]"))
			} else {
				tabs = append(tabs, dimStyle.Render(" "+label+" "))
			}
		}
		return strings.Join(tabs, "")
	}

	// Build a sliding window of tabs centered on current page
	buildSlidingTabs := func(tier int) string {
		// Pre-render all tabs
		rendered := make([]string, len(labels))
		widths := make([]int, len(labels))
		for i, lbl := range labels {
			var label string
			switch tier {
			case 0:
				label = lbl.full
			case 1:
				label = lbl.short
			default:
				label = lbl.tiny
			}
			if Page(i) == m.page {
				rendered[i] = headerStyle.Render("[" + label + "]")
			} else {
				rendered[i] = dimStyle.Render(" " + label + " ")
			}
			widths[i] = lipgloss.Width(rendered[i])
		}

		ellipsis := dimStyle.Render("..")
		ellipsisW := lipgloss.Width(ellipsis)
		cur := int(m.page)
		n := len(labels)

		// Start with current page, expand outward
		lo, hi := cur, cur
		usedW := widths[cur]

		for {
			expanded := false
			// Try expanding left
			if lo > 0 {
				needW := widths[lo-1]
				extra := 0
				if lo-1 > 0 {
					extra = ellipsisW // will need left ellipsis
				}
				if usedW+needW+extra <= m.width {
					lo--
					usedW += needW
					expanded = true
				}
			}
			// Try expanding right
			if hi < n-1 {
				needW := widths[hi+1]
				extra := 0
				if hi+1 < n-1 {
					extra = ellipsisW // will need right ellipsis
				}
				if usedW+needW+extra <= m.width {
					hi++
					usedW += needW
					expanded = true
				}
			}
			if !expanded {
				break
			}
		}

		var result string
		if lo > 0 {
			result += ellipsis
		}
		for i := lo; i <= hi; i++ {
			result += rendered[i]
		}
		if hi < n-1 {
			result += ellipsis
		}
		return result
	}

	left := buildTabs(0) // full labels

	// Indicators (paused, save msg, layout)
	var indicators string
	if m.paused {
		indicators += "  " + critStyle.Render("[PAUSED]")
	}
	if m.saveMsg != "" && time.Since(m.saveMsgTime) < 5*time.Second {
		indicators += "  " + okStyle.Render(m.saveMsg)
	}
	if m.beginnerMode {
		indicators += "  " + okStyle.Render("[Simple]")
	}
	if m.page == PageOverview && !m.beginnerMode {
		indicators += "  " + dimStyle.Render(fmt.Sprintf("[%s]", m.layoutMode))
	}

	help := helpStyle.Render("E:explain  I:probe  e:verdict  A/B:mode  v:layout  a:pause  S:save  ?:help  q:quit")

	// Try full tabs + indicators + help
	leftFull := left + indicators
	leftW := lipgloss.Width(leftFull)
	helpW := lipgloss.Width(help)

	if leftW+helpW+1 <= m.width {
		gap := m.width - leftW - helpW
		return leftFull + strings.Repeat(" ", gap) + help
	}

	// Try full tabs + indicators (drop help)
	if leftW <= m.width {
		return leftFull
	}

	// Try short tabs + indicators + help
	left = buildTabs(1) // short labels
	leftShort := left + indicators
	leftW = lipgloss.Width(leftShort)
	if leftW+helpW+1 <= m.width {
		gap := m.width - leftW - helpW
		return leftShort + strings.Repeat(" ", gap) + help
	}

	// Short tabs + indicators only
	if leftW <= m.width {
		return leftShort
	}

	// Try short tabs only (no indicators)
	leftW = lipgloss.Width(left)
	if leftW <= m.width {
		return left
	}

	// Try tiny (key-only) tabs + indicators
	left = buildTabs(2) // tiny labels
	leftTiny := left + indicators
	leftW = lipgloss.Width(leftTiny)
	if leftW <= m.width {
		return leftTiny
	}

	// Tiny tabs only
	leftW = lipgloss.Width(left)
	if leftW <= m.width {
		return left
	}

	// Last resort: sliding window of tiny tabs centered on current page
	return buildSlidingTabs(2)
}

// shortPageName returns an abbreviated page name for narrow terminals.
func shortPageName(name string) string {
	switch name {
	case "Overview":
		return "Ovr"
	case "Memory":
		return "Mem"
	case "Network":
		return "Net"
	case "CGroups":
		return "CG"
	case "Timeline":
		return "Tmln"
	case "Events":
		return "Evt"
	case "Probe":
		return "Prb"
	case "Thresholds":
		return "Thr"
	case "DiskGuard":
		return "Disk"
	case "Security":
		return "Sec"
	case "Logs":
		return "Log"
	case "Services":
		return "Svc"
	case "Diagnostics":
		return "Diag"
	default:
		return name
	}
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

		if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
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
	sb.WriteString("  D         DiskGuard (filesystem space monitor)\n")
	sb.WriteString("  L         Security (auth, SUID, fileless, ports)\n")
	sb.WriteString("  O         Logs (per-service error rates)\n")
	sb.WriteString("  H         Services (health probes, certs, DNS)\n")
	sb.WriteString("  W         Diagnostics (per-service deep analysis)\n")
	sb.WriteString("  b / Esc   Back to overview\n")
	sb.WriteString("\n")
	sb.WriteString(headerStyle.Render("Controls"))
	sb.WriteString("\n")
	sb.WriteString("  v/V       Cycle overview layout (F1-F4 for direct)\n")
	sb.WriteString("  D         DiskGuard page (filesystem space monitor)\n")
	sb.WriteString("  Ctrl+D    Set current layout as default\n")
	sb.WriteString("  a         Toggle auto-refresh (pause/resume)\n")
	sb.WriteString("  n         Step one frame (replay mode while paused)\n")
	sb.WriteString("  [ / ]     Replay seek -10 / +10 frames\n")
	sb.WriteString("  { / }     Replay seek -60 / +60 frames\n")
	sb.WriteString("  J / K     Replay jump to start / end\n")
	sb.WriteString("  I         Start eBPF probe investigation (auto-detect)\n")
	sb.WriteString("  S         Save RCA snapshot to JSON file\n")
	sb.WriteString("  E         Toggle explain side panel (metric glossary)\n")
	sb.WriteString("  e         Toggle explain verdict panel (evidence detail)\n")
	sb.WriteString("  P         Export incident report as markdown\n")
	sb.WriteString("  A         Switch to advanced mode\n")
	sb.WriteString("  B         Switch to simple/beginner mode\n")
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
	sb.WriteString("  Security   Failed auth, SUID changes, fileless, reverse shells\n")
	sb.WriteString("  Logs       Per-service error/warn rates with sparklines\n")
	sb.WriteString("  Services   HTTP/TCP probes, cert expiry, DNS resolution\n")
	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("Press any key to close"))
	return sb.String()
}

// diskGuardContain handles automatic freeze/resume in Contain/DryRun mode.
func (m *Model) diskGuardContain() {
	if m.result == nil || m.rates == nil {
		return
	}

	worst := m.result.DiskGuardWorst

	// Track stable period for cooldown reset
	if worst == "OK" {
		if m.stableStart.IsZero() {
			m.stableStart = time.Now()
		}
		// Reset incident action count after 30s continuous OK
		if time.Since(m.stableStart) >= 30*time.Second {
			m.incidentActionCount = 0
		}
	} else {
		m.stableStart = time.Time{}
	}

	// DryRun mode: log what WOULD happen but don't send signals
	if m.diskGuardMode == "DryRun" && worst == "CRIT" {
		procs := make([]model.ProcessRate, len(m.rates.ProcessRates))
		copy(procs, m.rates.ProcessRates)
		sort.Slice(procs, func(i, j int) bool {
			return procs[i].WriteMBs > procs[j].WriteMBs
		})
		for _, p := range procs {
			if p.WriteMBs < 0.5 {
				break
			}
			target := p.WritePath
			if target == "" {
				target = "unknown"
			}
			m.diskGuardMsg = fmt.Sprintf("Would freeze: PID %d (%s) writing %.1f MB/s to %s", p.PID, p.Comm, p.WriteMBs, target)
			m.diskGuardMsgT = time.Now()
			break // only show top writer
		}
	}

	// Contain mode: auto-freeze top writers when CRIT
	if m.diskGuardMode == "Contain" && worst == "CRIT" {
		// Cooldown: 60s after last action
		if !m.lastActionTime.IsZero() && time.Since(m.lastActionTime) < 60*time.Second {
			return
		}
		// Max 1 auto-freeze per incident
		if m.incidentActionCount >= 1 {
			return
		}

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
			// Denylist check
			if freezeDenylist[p.Comm] {
				m.diskGuardMsg = fmt.Sprintf("Skipped: PID %d (%s) is in denylist", p.PID, p.Comm)
				m.diskGuardMsgT = time.Now()
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
				m.lastActionTime = time.Now()
				m.incidentActionCount++
			}
			break // only freeze one per tick
		}
	}

	// Auto-resume when disk drops to OK (any mode) — only after 30s continuous OK
	if worst == "OK" && len(m.frozenPIDs) > 0 && !m.stableStart.IsZero() && time.Since(m.stableStart) >= 30*time.Second {
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
			m.diskGuardMsg = fmt.Sprintf("AUTO-RESUMED %d process(es) — disk OK for 30s", resumed)
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

// injectClock overlays "HH:MM:SS  every Ns" on the top-right of the first content line.
func (m Model) injectClock(content string) string {
	if m.width < 40 {
		return content
	}

	now := time.Now().Format("15:04:05")
	intervalStr := fmt.Sprintf("%.0fs", m.interval.Seconds())
	clock := dimStyle.Render(now+"  every "+intervalStr)
	clockW := lipgloss.Width(clock)

	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return content
	}

	firstLine := lines[0]
	lineW := lipgloss.Width(firstLine)
	gap := m.width - lineW - clockW
	if gap < 2 {
		// Not enough room — place on its own line
		return strings.Repeat(" ", m.width-clockW) + clock + "\n" + content
	}
	lines[0] = firstLine + strings.Repeat(" ", gap) + clock
	return strings.Join(lines, "\n")
}
