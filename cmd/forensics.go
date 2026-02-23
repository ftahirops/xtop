package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ForensicsEvent represents a single forensic finding.
type ForensicsEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`    // "dmesg", "journal", "sar", "auth"
	Category string    `json:"category"`  // "oom", "crash", "restart", "hardware", "security", "resource"
	Severity string    `json:"severity"`  // "info", "warn", "crit"
	Summary  string    `json:"summary"`
	Detail   string    `json:"detail,omitempty"`
}

// ForensicsReport holds the complete forensics analysis.
type ForensicsReport struct {
	Hostname    string                `json:"hostname"`
	AnalyzedAt  time.Time             `json:"analyzed_at"`
	Sessions    []model.ActiveSession `json:"active_sessions"` // #29: reuse model type
	UniqueIPs   int                   `json:"unique_session_ips"`
	Events      []ForensicsEvent      `json:"events"`
	OOMKills    int                   `json:"oom_kills"`
	Crashes     int                   `json:"crashes"`
	Restarts    int                   `json:"restarts"`
	HWErrors    int                   `json:"hw_errors"`
	SecurityEvt int                   `json:"security_events"`
}

const maxForensicsEvents = 5000 // #14: cap per parser

// runForensics performs retroactive incident analysis from system logs.
func runForensics(cfg Config) error {
	hostname, _ := os.Hostname()
	report := ForensicsReport{
		Hostname:   hostname,
		AnalyzedAt: time.Now(),
	}

	// Collect active sessions
	report.Sessions, report.UniqueIPs = collectActiveSessions()

	// Run all parsers (#14: cap total events)
	report.Events = append(report.Events, parseDmesg()...)
	report.Events = append(report.Events, parseJournalctl()...)
	report.Events = append(report.Events, parseSar()...)
	report.Events = append(report.Events, parseAuthLogForensics()...)

	// #14: Cap total events
	if len(report.Events) > maxForensicsEvents {
		report.Events = report.Events[:maxForensicsEvents]
	}

	// Sort by timestamp
	sort.Slice(report.Events, func(i, j int) bool {
		return report.Events[i].Timestamp.Before(report.Events[j].Timestamp)
	})

	// Count categories
	for _, evt := range report.Events {
		switch evt.Category {
		case "oom":
			report.OOMKills++
		case "crash":
			report.Crashes++
		case "restart":
			report.Restarts++
		case "hardware":
			report.HWErrors++
		case "security":
			report.SecurityEvt++
		}
	}

	// Output
	if cfg.JSONMode {
		return renderForensicsJSON(report)
	}
	if cfg.MDMode {
		return renderForensicsMD(report)
	}
	renderForensicsCLI(report)
	return nil
}

// ── Active Sessions ──────────────────────────────────────────────────────────

func collectActiveSessions() ([]model.ActiveSession, int) {
	var sessions []model.ActiveSession
	uniqueIPs := make(map[string]bool)

	out, err := exec.Command("w").Output()
	if err != nil {
		return sessions, 0
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return sessions, 0
	}

	header := lines[1]
	cols := []string{"USER", "TTY", "FROM", "LOGIN@", "IDLE", "JCPU", "PCPU", "WHAT"}
	pos := make(map[string]int)
	for _, col := range cols {
		idx := strings.Index(header, col)
		if idx >= 0 {
			pos[col] = idx
		}
	}

	// Need at minimum USER, FROM, WHAT
	if _, ok := pos["USER"]; !ok {
		return sessions, 0
	}
	if _, ok := pos["WHAT"]; !ok {
		return sessions, 0
	}

	for _, line := range lines[2:] {
		if line == "" || len(line) < pos["WHAT"] {
			continue
		}

		user := strings.TrimSpace(safeSlice(line, pos["USER"], pos["TTY"]))
		tty := strings.TrimSpace(safeSlice(line, pos["TTY"], pos["FROM"]))
		from := strings.TrimSpace(safeSlice(line, pos["FROM"], pos["LOGIN@"]))
		loginAt := strings.TrimSpace(safeSlice(line, pos["LOGIN@"], pos["IDLE"]-1))
		idle := strings.TrimSpace(safeSlice(line, pos["IDLE"]-1, pos["JCPU"]))
		cmd := strings.TrimSpace(safeSlice(line, pos["WHAT"], len(line)))

		if from != "" && from != "-" {
			uniqueIPs[from] = true
		}

		sessions = append(sessions, model.ActiveSession{
			User:    user,
			TTY:     tty,
			From:    from,
			LoginAt: loginAt,
			Idle:    idle,
			Command: cmd,
		})
	}

	return sessions, len(uniqueIPs)
}

// #8: safeSlice with proper guards for end < start and end < 0
func safeSlice(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end < 0 {
		end = 0
	}
	if start >= len(s) {
		return ""
	}
	if end > len(s) {
		end = len(s)
	}
	if end <= start {
		return ""
	}
	return s[start:end]
}

// ── Parsers ──────────────────────────────────────────────────────────────────

func parseDmesg() []ForensicsEvent {
	var events []ForensicsEvent

	out, err := exec.Command("dmesg", "--time-format=iso", "--level=err,warn,crit,alert,emerg").Output()
	if err != nil {
		return events
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		if len(events) >= maxForensicsEvents {
			break
		}

		ts, msg := parseDmesgLine(line)

		lower := strings.ToLower(msg)
		switch {
		case strings.Contains(lower, "out of memory: kill"):
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "dmesg",
				Category: "oom",
				Severity: "crit",
				Summary:  "OOM killer invoked",
				Detail:   truncateForensics(msg, 200),
			})
		case strings.Contains(lower, "hardware error"):
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "dmesg",
				Category: "hardware",
				Severity: "crit",
				Summary:  "Hardware error detected",
				Detail:   truncateForensics(msg, 200),
			})
		case strings.Contains(lower, "i/o error"):
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "dmesg",
				Category: "hardware",
				Severity: "crit",
				Summary:  "I/O error on block device",
				Detail:   truncateForensics(msg, 200),
			})
		case strings.Contains(lower, "hung_task_timeout"):
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "dmesg",
				Category: "hardware",
				Severity: "warn",
				Summary:  "Hung task detected",
				Detail:   truncateForensics(msg, 200),
			})
		case strings.Contains(lower, "ext4-fs error") || strings.Contains(lower, "xfs error"):
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "dmesg",
				Category: "hardware",
				Severity: "crit",
				Summary:  "Filesystem error",
				Detail:   truncateForensics(msg, 200),
			})
		}
	}
	return events
}

// #20: Fix dmesg timestamp parsing — use -0700 for proper timezone handling
func parseDmesgLine(line string) (time.Time, string) {
	// Try to find the timestamp-message boundary by looking for a space after the timezone
	// Format: "2026-02-22T14:22:15,000000+0000 message" or "2026-02-22T14:22:15,000000+00:00 message"
	// Find first space after the T to split timestamp from message
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 2 && len(parts[0]) >= 25 {
		tsStr := strings.Replace(parts[0], ",", ".", 1)
		// Try various timezone formats
		for _, layout := range []string{
			"2006-01-02T15:04:05.000000-0700",
			"2006-01-02T15:04:05.000000-07:00",
			"2006-01-02T15:04:05.000000Z",
			"2006-01-02T15:04:05-0700",
			"2006-01-02T15:04:05-07:00",
		} {
			if t, err := time.Parse(layout, tsStr); err == nil {
				return t, parts[1]
			}
		}
	}
	return time.Now(), line
}

// #14: Stream journalctl output instead of buffering everything in memory
func parseJournalctl() []ForensicsEvent {
	var events []ForensicsEvent

	cmd := exec.Command("journalctl", "--since", "24 hours ago",
		"-p", "err", "--no-pager", "-o", "json", "--lines=10000")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return events
	}
	if err := cmd.Start(); err != nil {
		return events
	}
	defer cmd.Wait()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	for scanner.Scan() {
		if len(events) >= maxForensicsEvents {
			break
		}

		var entry map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		msg, _ := entry["MESSAGE"].(string)
		unit, _ := entry["_SYSTEMD_UNIT"].(string)
		lower := strings.ToLower(msg)

		// Parse timestamp
		ts := time.Now()
		if usecStr, ok := entry["__REALTIME_TIMESTAMP"].(string); ok {
			if usec, err := strconv.ParseInt(usecStr, 10, 64); err == nil {
				ts = time.Unix(usec/1000000, (usec%1000000)*1000)
			}
		}

		switch {
		case strings.Contains(lower, "entered failed state") || strings.Contains(lower, "failed with result"):
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "journal",
				Category: "crash",
				Severity: "crit",
				Summary:  fmt.Sprintf("Service crashed: %s", unit),
				Detail:   truncateForensics(msg, 200),
			})
		// #17(forensics): Only match systemd "Started" messages, not arbitrary app logs
		case unit == "init.scope" || strings.HasSuffix(unit, ".service"):
			if strings.Contains(lower, "started ") && strings.HasPrefix(lower, "started ") {
				events = append(events, ForensicsEvent{
					Timestamp: ts,
					Source:    "journal",
					Category: "restart",
					Severity: "warn",
					Summary:  fmt.Sprintf("Service restarted: %s", unit),
					Detail:   truncateForensics(msg, 200),
				})
			}
		case strings.Contains(lower, "kernel") && strings.Contains(lower, "error"):
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "journal",
				Category: "hardware",
				Severity: "crit",
				Summary:  "Kernel error",
				Detail:   truncateForensics(msg, 200),
			})
		}
	}

	return events
}

func parseSar() []ForensicsEvent {
	var events []ForensicsEvent

	// Find sar data files
	sarDirs := []string{"/var/log/sysstat", "/var/log/sa"}
	var sarFile string
	for _, dir := range sarDirs {
		matches, _ := filepath.Glob(dir + "/sa[0-9]*")
		if len(matches) > 0 {
			sort.Strings(matches)
			sarFile = matches[len(matches)-1]
			break
		}
	}
	if sarFile == "" {
		return events
	}

	// #10: Extract the day from the sar filename for correct date assignment
	sarDay := extractSarDay(sarFile)

	// Check CPU saturation
	cpuOut, err := exec.Command("sar", "-u", "-f", sarFile).Output()
	if err == nil {
		events = append(events, parseSarCPU(string(cpuOut), sarDay)...)
	}

	// Check memory
	memOut, err := exec.Command("sar", "-r", "-f", sarFile).Output()
	if err == nil {
		events = append(events, parseSarMem(string(memOut), sarDay)...)
	}

	return events
}

// extractSarDay extracts the day of month from sar filename (e.g., "/var/log/sa/sa22" -> 22)
func extractSarDay(path string) int {
	base := filepath.Base(path)
	// Strip "sa" prefix
	dayStr := strings.TrimPrefix(base, "sa")
	day, err := strconv.Atoi(dayStr)
	if err != nil || day < 1 || day > 31 {
		return time.Now().Day()
	}
	return day
}

var sarTimeRE = regexp.MustCompile(`^(\d{2}:\d{2}:\d{2})`)

func parseSarCPU(output string, sarDay int) []ForensicsEvent {
	var events []ForensicsEvent
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if len(events) >= maxForensicsEvents {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if !sarTimeRE.MatchString(fields[0]) {
			continue
		}

		// %idle is typically the last field
		idleStr := fields[len(fields)-1]
		idle, err := strconv.ParseFloat(idleStr, 64)
		if err != nil {
			continue
		}

		if idle < 5 { // CPU > 95%
			ts := parseSarTimeWithDay(fields[0], sarDay)
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "sar",
				Category: "resource",
				Severity: "warn",
				Summary:  fmt.Sprintf("CPU saturated: %.0f%% busy", 100-idle),
				Detail:   line,
			})
		}
	}
	return events
}

func parseSarMem(output string, sarDay int) []ForensicsEvent {
	var events []ForensicsEvent
	lines := strings.Split(output, "\n")

	// Find %memused column index from header
	memUsedCol := -1
	for _, line := range lines {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "%memused" {
				memUsedCol = i
				break
			}
		}
		if memUsedCol >= 0 {
			break
		}
	}
	if memUsedCol < 0 {
		return events
	}

	for _, line := range lines {
		if len(events) >= maxForensicsEvents {
			break
		}
		fields := strings.Fields(line)
		if len(fields) <= memUsedCol {
			continue
		}
		if !sarTimeRE.MatchString(fields[0]) {
			continue
		}

		memUsed, err := strconv.ParseFloat(fields[memUsedCol], 64)
		if err != nil {
			continue
		}
		if memUsed > 95 && memUsed <= 100 {
			ts := parseSarTimeWithDay(fields[0], sarDay)
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "sar",
				Category: "resource",
				Severity: "warn",
				Summary:  fmt.Sprintf("Memory saturated: %.0f%% used", memUsed),
				Detail:   line,
			})
		}
	}
	return events
}

// #10: parseSarTimeWithDay uses the correct day from the sar filename
func parseSarTimeWithDay(timeStr string, day int) time.Time {
	now := time.Now()
	t, err := time.Parse("15:04:05", timeStr)
	if err != nil {
		return now
	}
	return time.Date(now.Year(), now.Month(), day,
		t.Hour(), t.Minute(), t.Second(), 0, now.Location())
}

var authFailedRE = regexp.MustCompile(`Failed password.*from\s+(\S+)`)

func parseAuthLogForensics() []ForensicsEvent {
	var events []ForensicsEvent

	const authLog = "/var/log/auth.log"
	f, err := os.Open(authLog)
	if err != nil {
		return events
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return events
	}
	// #11(forensics): Seek to last 1MB, then discard partial first line
	if fi.Size() > 1024*1024 {
		f.Seek(fi.Size()-1024*1024, 0)
	}

	failCount := 0
	minuteWindow := make(map[string]int)
	var rootLogins []ForensicsEvent

	scanner := bufio.NewScanner(f)

	// Discard first partial line after seek
	if fi.Size() > 1024*1024 {
		scanner.Scan()
	}

	for scanner.Scan() {
		if len(events) >= maxForensicsEvents {
			break
		}
		line := scanner.Text()
		lower := strings.ToLower(line)

		// Failed auth
		if m := authFailedRE.FindStringSubmatch(line); m != nil {
			failCount++
			ts := parseAuthLogTime(line)
			minute := ts.Format("15:04")
			minuteWindow[minute]++
		}

		// Successful root login
		if strings.Contains(lower, "accepted") && strings.Contains(lower, "root") {
			ts := parseAuthLogTime(line)
			rootLogins = append(rootLogins, ForensicsEvent{
				Timestamp: ts,
				Source:    "auth",
				Category: "security",
				Severity: "warn",
				Summary:  "Successful root login",
				Detail:   truncateForensics(line, 200),
			})
		}

		// Sudo failures
		if strings.Contains(lower, "sudo") && strings.Contains(lower, "authentication failure") {
			ts := parseAuthLogTime(line)
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "auth",
				Category: "security",
				Severity: "warn",
				Summary:  "Sudo authentication failure",
				Detail:   truncateForensics(line, 200),
			})
		}
	}

	// Detect brute force bursts (>10 failures in any minute)
	for minute, count := range minuteWindow {
		if count > 10 {
			ts := parseSarTimeWithDay(minute+":00", time.Now().Day())
			events = append(events, ForensicsEvent{
				Timestamp: ts,
				Source:    "auth",
				Category: "security",
				Severity: "crit",
				Summary:  fmt.Sprintf("Brute force burst: %d failed logins/min", count),
			})
		}
	}

	if failCount > 0 {
		events = append(events, ForensicsEvent{
			Timestamp: time.Now(),
			Source:    "auth",
			Category: "security",
			Severity: "info",
			Summary:  fmt.Sprintf("%d failed SSH logins in analyzed period", failCount),
		})
	}

	events = append(events, rootLogins...)
	return events
}

var authLogTimeRE = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})`)
var authLogISOTimeRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)

func parseAuthLogTime(line string) time.Time {
	// Try ISO format first: 2026-02-22T04:00:42.777733+00:00
	if m := authLogISOTimeRE.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse("2006-01-02T15:04:05", m[1]); err == nil {
			return t
		}
	}

	// Traditional syslog format: Feb 22 04:00:42
	if m := authLogTimeRE.FindStringSubmatch(line); m != nil {
		now := time.Now()
		t, err := time.Parse("Jan  2 15:04:05", m[1])
		if err != nil {
			t, err = time.Parse("Jan 2 15:04:05", m[1])
			if err != nil {
				return now
			}
		}
		return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
	}

	return time.Now()
}

// ── Renderers ────────────────────────────────────────────────────────────────

func renderForensicsCLI(report ForensicsReport) {
	// Header
	fmt.Printf("\n \033[1;36mxtop forensics v%s\033[0m — %s  %s\n\n",
		Version, report.Hostname, report.AnalyzedAt.Format("2006-01-02 15:04:05"))

	// Active sessions
	fmt.Printf(" \033[90m── Active Sessions (%d sessions, %d unique IPs) %s\033[0m\n",
		len(report.Sessions), report.UniqueIPs, strings.Repeat("─", 30))

	if len(report.Sessions) == 0 {
		fmt.Printf("  \033[90mNo active sessions\033[0m\n")
	} else {
		fmt.Printf("  \033[35;1m%-10s %-8s %-22s %-8s %-6s %s\033[0m\n",
			"USER", "TTY", "FROM", "LOGIN@", "IDLE", "COMMAND")
		fmt.Printf("  \033[90m%s\033[0m\n", strings.Repeat("─", 76))
		for _, s := range report.Sessions {
			fromStr := s.From
			if fromStr == "-" || fromStr == "" {
				fromStr = "\033[90mlocal\033[0m"
			}
			idleColor := "0" // normal
			if s.Idle == "0.00s" || s.Idle == "." {
				idleColor = "32" // green = active right now
			}
			fmt.Printf("  \033[1m%-10s\033[0m %-8s %-22s %-8s \033[%sm%-6s\033[0m %s\n",
				s.User, s.TTY, fromStr, s.LoginAt, idleColor, s.Idle, s.Command)
		}
	}
	fmt.Println()

	// Timeline
	fmt.Printf(" \033[90m── Timeline (last 24h) %s\033[0m\n", strings.Repeat("─", 45))

	if len(report.Events) == 0 {
		fmt.Printf("  \033[32mNo events found — system appears stable\033[0m\n")
	} else {
		for _, evt := range report.Events {
			sevColor := "32" // green/info
			switch evt.Severity {
			case "warn":
				sevColor = "33" // yellow
			case "crit":
				sevColor = "31" // red
			}
			ts := evt.Timestamp.Format("15:04:05")
			fmt.Printf("  %s  \033[%s;1m%-4s\033[0m  \033[90m[%-10s]\033[0m  %s\n",
				ts, sevColor, strings.ToUpper(evt.Severity), evt.Category, evt.Summary)
		}
	}

	// Summary
	fmt.Printf("\n \033[90m── Summary %s\033[0m\n", strings.Repeat("─", 56))
	fmt.Printf("  OOM Kills: \033[1m%d\033[0m   Crashes: \033[1m%d\033[0m   Restarts: \033[1m%d\033[0m   HW Errors: \033[1m%d\033[0m   Security: \033[1m%d\033[0m\n",
		report.OOMKills, report.Crashes, report.Restarts, report.HWErrors, report.SecurityEvt)
	fmt.Printf("  Total: %d events in last 24 hours\n\n", len(report.Events))
}

func renderForensicsJSON(report ForensicsReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderForensicsMD(report ForensicsReport) error {
	fmt.Printf("# xtop Forensics Report\n\n")
	fmt.Printf("**Host:** %s\n", report.Hostname)
	fmt.Printf("**Analyzed:** %s\n\n", report.AnalyzedAt.Format(time.RFC3339))

	// Active sessions
	fmt.Printf("## Active Sessions (%d sessions, %d unique IPs)\n\n", len(report.Sessions), report.UniqueIPs)
	if len(report.Sessions) == 0 {
		fmt.Printf("No active sessions.\n\n")
	} else {
		fmt.Printf("| User | TTY | From | Login | Idle | Command |\n")
		fmt.Printf("|------|-----|------|-------|------|---------|\n")
		for _, s := range report.Sessions {
			from := s.From
			if from == "-" || from == "" {
				from = "local"
			}
			fmt.Printf("| %s | %s | %s | %s | %s | `%s` |\n",
				s.User, s.TTY, from, s.LoginAt, s.Idle, s.Command)
		}
		fmt.Println()
	}

	fmt.Printf("## Summary\n\n")
	fmt.Printf("| Category | Count |\n")
	fmt.Printf("|----------|-------|\n")
	fmt.Printf("| OOM Kills | %d |\n", report.OOMKills)
	fmt.Printf("| Crashes | %d |\n", report.Crashes)
	fmt.Printf("| Restarts | %d |\n", report.Restarts)
	fmt.Printf("| HW Errors | %d |\n", report.HWErrors)
	fmt.Printf("| Security | %d |\n", report.SecurityEvt)
	fmt.Printf("| **Total** | **%d** |\n\n", len(report.Events))

	if len(report.Events) > 0 {
		fmt.Printf("## Timeline\n\n")
		fmt.Printf("| Time | Severity | Category | Summary |\n")
		fmt.Printf("|------|----------|----------|---------|\n")
		for _, evt := range report.Events {
			fmt.Printf("| %s | %s | %s | %s |\n",
				evt.Timestamp.Format("15:04:05"),
				strings.ToUpper(evt.Severity),
				evt.Category, evt.Summary)
		}
	}

	fmt.Printf("\n---\n*Generated by [xtop](https://github.com/ftahirops/xtop) forensics*\n")
	return nil
}

func truncateForensics(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
