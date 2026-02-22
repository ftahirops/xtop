package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runShellInit outputs an eval-able shell init script for bash or zsh.
func runShellInit(shell string, dataDir string) {
	switch shell {
	case "bash":
		fmt.Println(bashInitScript(dataDir))
	case "zsh":
		fmt.Println(zshInitScript(dataDir))
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported shell %q (use bash or zsh)\n", shell)
		os.Exit(1)
	}
}

func bashInitScript(dataDir string) string {
	return fmt.Sprintf(`# xtop shell health widget — add to .bashrc:
#   eval "$(xtop -shell-init bash)"

_xtop_widget() {
    local file="%s/current.jsonl"
    [ -f "$file" ] || return

    local line
    line=$(tail -n 1 "$file" 2>/dev/null)
    [ -z "$line" ] && return

    local health="" bottleneck="" process="" hidden="" cpu="" mem="" disk=""
    health=$(echo "$line" | grep -o '"health":"[^"]*"' | cut -d'"' -f4)
    bottleneck=$(echo "$line" | grep -o '"bottleneck":"[^"]*"' | cut -d'"' -f4)
    process=$(echo "$line" | grep -o '"process":"[^"]*"' | cut -d'"' -f4)
    hidden=$(echo "$line" | grep -o '"hidden_latency":true')
    cpu=$(echo "$line" | grep -o '"cpu_busy":[0-9.]*' | cut -d: -f2)
    mem=$(echo "$line" | grep -o '"mem_pct":[0-9.]*' | cut -d: -f2)
    disk=$(echo "$line" | grep -o '"disk_state":"[^"]*"' | cut -d'"' -f4)

    [ -z "$cpu" ] && return

    # Stale detection (>30s old)
    local ts
    ts=$(echo "$line" | grep -o '"ts":"[^"]*"' | cut -d'"' -f4)
    if command -v date >/dev/null 2>&1; then
        local now ts_epoch
        now=$(date +%%s 2>/dev/null)
        ts_epoch=$(date -d "$ts" +%%s 2>/dev/null)
        if [ -n "$now" ] && [ -n "$ts_epoch" ]; then
            local age=$((now - ts_epoch))
            if [ "$age" -gt 30 ]; then
                printf '\n\033[2m[xtop stale %%ds]\033[0m\n' "$age"
                return
            fi
        fi
    fi

    # SILENT when healthy
    if [ "$health" = "CRITICAL" ] && [ -n "$bottleneck" ]; then
        local msg="\033[1;31m✗ ${bottleneck}\033[0m"
        [ -n "$process" ] && msg="$msg \033[2m(${process})\033[0m"
        printf '\n%%b\n' "$msg"
        return
    fi
    if [ "$health" = "DEGRADED" ] && [ -n "$bottleneck" ]; then
        printf '\n\033[33m⚠ %%s\033[0m\n' "$bottleneck"
        return
    fi
    if [ -n "$hidden" ]; then
        printf '\n\033[33m⚠ hidden latency\033[0m\n'
        return
    fi

    # Individual thresholds
    local cpu_int=${cpu%%%%.*} mem_int=${mem%%%%.*} parts=""
    [ "$cpu_int" -gt 90 ] 2>/dev/null && parts="${parts}\033[31mC:${cpu_int}%%%%\033[0m "
    [ "$cpu_int" -gt 70 ] 2>/dev/null && [ "$cpu_int" -le 90 ] 2>/dev/null && parts="${parts}\033[33mC:${cpu_int}%%%%\033[0m "
    [ "$mem_int" -gt 85 ] 2>/dev/null && parts="${parts}\033[31mM:${mem_int}%%%%\033[0m "
    [ "$mem_int" -gt 70 ] 2>/dev/null && [ "$mem_int" -le 85 ] 2>/dev/null && parts="${parts}\033[33mM:${mem_int}%%%%\033[0m "
    [ "$disk" = "CRIT" ] && parts="${parts}\033[31mD:CRIT\033[0m "
    [ "$disk" = "WARN" ] && parts="${parts}\033[33mD:WARN\033[0m "

    [ -n "$parts" ] && printf '\n%%b\n' "$parts"
}

# Auto-start daemon if not running (root only)
if [ "$(id -u)" = "0" ]; then
    if [ ! -f "%s/daemon.pid" ] || ! kill -0 "$(cat "%s/daemon.pid" 2>/dev/null)" 2>/dev/null; then
        /usr/local/bin/xtop -daemon &>/dev/null &
        disown
    fi
fi

# Guard against duplicate registration
case "$PROMPT_COMMAND" in
    *_xtop_widget*) ;;
    *) PROMPT_COMMAND="_xtop_widget;${PROMPT_COMMAND}" ;;
esac
`, dataDir, dataDir, dataDir)
}

func zshInitScript(dataDir string) string {
	return fmt.Sprintf(`# xtop shell health widget — add to .zshrc:
#   eval "$(xtop -shell-init zsh)"

_xtop_widget() {
    local file="%s/current.jsonl"
    [[ -f "$file" ]] || return

    local line
    line=$(tail -n 1 "$file" 2>/dev/null)
    [[ -z "$line" ]] && return

    local health="" bottleneck="" process="" hidden="" cpu="" mem="" disk=""
    health=$(echo "$line" | grep -o '"health":"[^"]*"' | cut -d'"' -f4)
    bottleneck=$(echo "$line" | grep -o '"bottleneck":"[^"]*"' | cut -d'"' -f4)
    process=$(echo "$line" | grep -o '"process":"[^"]*"' | cut -d'"' -f4)
    hidden=$(echo "$line" | grep -o '"hidden_latency":true')
    cpu=$(echo "$line" | grep -o '"cpu_busy":[0-9.]*' | cut -d: -f2)
    mem=$(echo "$line" | grep -o '"mem_pct":[0-9.]*' | cut -d: -f2)
    disk=$(echo "$line" | grep -o '"disk_state":"[^"]*"' | cut -d'"' -f4)

    [[ -z "$cpu" ]] && return

    # Stale detection
    local ts
    ts=$(echo "$line" | grep -o '"ts":"[^"]*"' | cut -d'"' -f4)
    if (( $+commands[date] )); then
        local now=$(date +%%s 2>/dev/null)
        local ts_epoch=$(date -d "$ts" +%%s 2>/dev/null)
        if [[ -n "$now" && -n "$ts_epoch" ]]; then
            local age=$((now - ts_epoch))
            if (( age > 30 )); then
                print "\n%%F{242}[xtop stale ${age}s]%%f"
                return
            fi
        fi
    fi

    # SILENT when healthy
    if [[ "$health" = "CRITICAL" && -n "$bottleneck" ]]; then
        local msg="%%B%%F{red}✗ ${bottleneck}%%f%%b"
        [[ -n "$process" ]] && msg="$msg %%F{242}(${process})%%f"
        print "\n${msg}"
        return
    fi
    if [[ "$health" = "DEGRADED" && -n "$bottleneck" ]]; then
        print "\n%%F{yellow}⚠ ${bottleneck}%%f"
        return
    fi
    if [[ -n "$hidden" ]]; then
        print "\n%%F{yellow}⚠ hidden latency%%f"
        return
    fi

    # Individual thresholds
    local cpu_int=${cpu%%%%.*} mem_int=${mem%%%%.*} parts=""
    (( cpu_int > 90 )) && parts="${parts}%%F{red}C:${cpu_int}%%%%%%f "
    (( cpu_int > 70 && cpu_int <= 90 )) && parts="${parts}%%F{yellow}C:${cpu_int}%%%%%%f "
    (( mem_int > 85 )) && parts="${parts}%%F{red}M:${mem_int}%%%%%%f "
    (( mem_int > 70 && mem_int <= 85 )) && parts="${parts}%%F{yellow}M:${mem_int}%%%%%%f "
    [[ "$disk" = "CRIT" ]] && parts="${parts}%%F{red}D:CRIT%%f "
    [[ "$disk" = "WARN" ]] && parts="${parts}%%F{yellow}D:WARN%%f "

    [[ -n "$parts" ]] && print "\n${parts}"
}

# Auto-start daemon if not running (root only)
if [[ "$EUID" = "0" ]]; then
    if [[ ! -f "%s/daemon.pid" ]] || ! kill -0 "$(cat "%s/daemon.pid" 2>/dev/null)" 2>/dev/null; then
        /usr/local/bin/xtop -daemon &>/dev/null &!
    fi
fi

# Guard against duplicate registration
if (( ${precmd_functions[(I)_xtop_widget]} == 0 )); then
    precmd_functions+=(_xtop_widget)
fi
`, dataDir, dataDir, dataDir)
}

// runTmuxStatus outputs a tmux-formatted status string with smart alerts.
func runTmuxStatus(dataDir string) {
	summaryPath := filepath.Join(dataDir, "current.jsonl")

	data, err := os.ReadFile(summaryPath)
	if err != nil {
		fmt.Print("#[fg=colour242]xtop:N/A")
		return
	}

	// Read last line
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		fmt.Print("#[fg=colour242]xtop:N/A")
		return
	}
	lastLine := lines[len(lines)-1]

	var s struct {
		Timestamp     time.Time `json:"ts"`
		Health        string    `json:"health"`
		Score         int       `json:"score"`
		Bottleneck    string    `json:"bottleneck"`
		CPUBusy       float64   `json:"cpu_busy"`
		MemPct        float64   `json:"mem_pct"`
		DiskState     string    `json:"disk_state"`
		NetState      string    `json:"net_state"`
		Process       string    `json:"process"`
		HiddenLatency bool      `json:"hidden_latency"`
	}
	if err := json.Unmarshal([]byte(lastLine), &s); err != nil {
		fmt.Print("#[fg=colour242]xtop:ERR")
		return
	}

	// Stale check
	age := time.Since(s.Timestamp).Seconds()
	if age > 30 {
		fmt.Printf("#[fg=colour242]xtop:stale %.0fs", age)
		return
	}

	// Smart alert: show bottleneck when system is unhealthy
	if s.Health == "CRITICAL" && s.Bottleneck != "" {
		msg := fmt.Sprintf("#[fg=colour196,bold]✗ %s", s.Bottleneck)
		if s.Process != "" {
			msg += fmt.Sprintf(" (%s)", s.Process)
		}
		fmt.Printf("%s [%d%%%%]#[default]", msg, s.Score)
		return
	}
	if s.Health == "DEGRADED" && s.Bottleneck != "" {
		msg := fmt.Sprintf("#[fg=colour226,bold]⚠ %s", s.Bottleneck)
		if s.Process != "" {
			msg += fmt.Sprintf(" (%s)", s.Process)
		}
		fmt.Printf("%s#[default]", msg)
		return
	}
	if s.HiddenLatency {
		fmt.Print("#[fg=colour226]⚠ Hidden latency#[default]")
		return
	}

	// Normal: compact metrics
	tmuxColor := func(val float64, warn, crit float64) string {
		if val > crit {
			return "#[fg=colour196]"
		}
		if val > warn {
			return "#[fg=colour226]"
		}
		return "#[fg=colour82]"
	}
	stateColor := func(state string) string {
		switch state {
		case "CRIT", "CRITICAL":
			return "#[fg=colour196]"
		case "WARN", "DEGRADED":
			return "#[fg=colour226]"
		}
		return "#[fg=colour82]"
	}

	// Silent when healthy — only show what's bad
	var parts []string
	if s.CPUBusy > 70 {
		parts = append(parts, fmt.Sprintf("%sC:%.0f%%%%", tmuxColor(s.CPUBusy, 70, 90), s.CPUBusy))
	}
	if s.MemPct > 70 {
		parts = append(parts, fmt.Sprintf("%sM:%.0f%%%%", tmuxColor(s.MemPct, 70, 85), s.MemPct))
	}
	if s.DiskState != "OK" && s.DiskState != "" {
		parts = append(parts, fmt.Sprintf("%sD:%s", stateColor(s.DiskState), s.DiskState))
	}
	if len(parts) > 0 {
		fmt.Printf("%s#[default]", strings.Join(parts, " "))
	}
}

// runCronInstall prints a crontab line for automated health checks.
func runCronInstall() {
	fmt.Println("# xtop automated health check — add to crontab with: crontab -e")
	fmt.Println("# Runs every 5 minutes, only alerts on state changes")
	fmt.Println("*/5 * * * * /usr/local/bin/xtop -doctor -alert -interval 1 2>/dev/null")
}
