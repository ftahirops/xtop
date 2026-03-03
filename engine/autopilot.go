package engine

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// protectedServices cannot be targeted by autopilot actions.
var protectedServices = map[string]bool{
	"sshd": true, "systemd": true, "systemd-journald": true,
	"haproxy": true, "nginx": true, "containerd": true,
	"dockerd": true, "kubelet": true, "init": true,
}

// AutopilotConfig configures the autopilot subsystem.
type AutopilotConfig struct {
	Enabled            bool     `json:"enabled"`
	AutoConfirm        bool     `json:"auto_confirm"` // skip confirmation prompts
	ProtectedServices  []string `json:"protected_services,omitempty"`
	MaxCPUQuotaUs      int      `json:"max_cpu_quota_us,omitempty"`  // min CPU quota to set (default 10000)
	MaxMemLimitMB      int      `json:"max_mem_limit_mb,omitempty"`  // min mem limit in MB
	RollbackTimeoutSec int      `json:"rollback_timeout_sec,omitempty"` // auto-rollback timeout (default 60)
}

// ActionType identifies the kind of autopilot action.
type ActionType string

const (
	ActionThrottleCPU   ActionType = "throttle_cpu"
	ActionIsolateProc   ActionType = "isolate_process"
	ActionSetIONice     ActionType = "set_ionice"
)

// AutopilotAction records an action taken by the autopilot for rollback.
type AutopilotAction struct {
	Type      ActionType
	PID       int
	Comm      string
	Cgroup    string
	OldValue  string // original value for rollback
	NewValue  string
	Timestamp time.Time
}

// Autopilot manages safe automated remediation actions.
type Autopilot struct {
	enabled    bool
	config     AutopilotConfig
	actions    []AutopilotAction
	maxActions int
	mu         sync.Mutex
}

// NewAutopilot creates a new autopilot instance.
func NewAutopilot(cfg AutopilotConfig) *Autopilot {
	// Add user-configured protected services
	for _, svc := range cfg.ProtectedServices {
		protectedServices[svc] = true
	}

	maxActions := 10
	if cfg.MaxCPUQuotaUs == 0 {
		cfg.MaxCPUQuotaUs = 10000 // 10ms = 1% of one CPU
	}
	if cfg.RollbackTimeoutSec == 0 {
		cfg.RollbackTimeoutSec = 60
	}

	return &Autopilot{
		enabled:    cfg.Enabled,
		config:     cfg,
		maxActions: maxActions,
	}
}

// IsProtected returns true if the process is protected from autopilot actions.
func (a *Autopilot) IsProtected(comm string) bool {
	return protectedServices[comm]
}

// ThrottleCPU sets CPU quota on a cgroup to limit its CPU usage.
func (a *Autopilot) ThrottleCPU(cgroup string, quotaUs int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return fmt.Errorf("autopilot disabled")
	}
	if len(a.actions) >= a.maxActions {
		return fmt.Errorf("max actions reached (%d)", a.maxActions)
	}
	if quotaUs < a.config.MaxCPUQuotaUs {
		quotaUs = a.config.MaxCPUQuotaUs
	}

	// Read current quota for rollback
	quotaPath := fmt.Sprintf("/sys/fs/cgroup%s/cpu.max", cgroup)
	oldValue := ""
	if data, err := os.ReadFile(quotaPath); err == nil {
		oldValue = strings.TrimSpace(string(data))
	}

	// Write new quota
	newValue := fmt.Sprintf("%d 100000", quotaUs) // quota per 100ms period
	if err := os.WriteFile(quotaPath, []byte(newValue), 0644); err != nil {
		return fmt.Errorf("set cpu quota: %w", err)
	}

	a.actions = append(a.actions, AutopilotAction{
		Type:      ActionThrottleCPU,
		Cgroup:    cgroup,
		OldValue:  oldValue,
		NewValue:  newValue,
		Timestamp: time.Now(),
	})
	log.Printf("AUTOPILOT: throttle CPU %s → %s", cgroup, newValue)
	return nil
}

// IsolateProcess moves a process to an xtop-jail cgroup.
func (a *Autopilot) IsolateProcess(pid int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return fmt.Errorf("autopilot disabled")
	}
	if len(a.actions) >= a.maxActions {
		return fmt.Errorf("max actions reached")
	}

	// Read current cgroup for rollback
	cgPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	oldCgroup := ""
	if data, err := os.ReadFile(cgPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 {
			parts := strings.SplitN(lines[0], "::", 2)
			if len(parts) == 2 {
				oldCgroup = parts[1]
			}
		}
	}

	// Create jail cgroup
	jailPath := "/sys/fs/cgroup/xtop-jail"
	os.MkdirAll(jailPath, 0755)

	// Move process
	procsPath := jailPath + "/cgroup.procs"
	if err := os.WriteFile(procsPath, []byte(fmt.Sprintf("%d\n", pid)), 0644); err != nil {
		return fmt.Errorf("isolate process: %w", err)
	}

	a.actions = append(a.actions, AutopilotAction{
		Type:      ActionIsolateProc,
		PID:       pid,
		Cgroup:    "xtop-jail",
		OldValue:  oldCgroup,
		Timestamp: time.Now(),
	})
	log.Printf("AUTOPILOT: isolated PID %d to xtop-jail", pid)
	return nil
}

// SetIONice changes the IO scheduling class/priority of a process.
func (a *Autopilot) SetIONice(pid, class, level int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return fmt.Errorf("autopilot disabled")
	}
	if len(a.actions) >= a.maxActions {
		return fmt.Errorf("max actions reached")
	}

	cmd := exec.Command("ionice", "-c", fmt.Sprintf("%d", class),
		"-n", fmt.Sprintf("%d", level), "-p", fmt.Sprintf("%d", pid))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ionice: %w", err)
	}

	a.actions = append(a.actions, AutopilotAction{
		Type:      ActionSetIONice,
		PID:       pid,
		NewValue:  fmt.Sprintf("class=%d,level=%d", class, level),
		Timestamp: time.Now(),
	})
	log.Printf("AUTOPILOT: ionice PID %d class=%d level=%d", pid, class, level)
	return nil
}

// Rollback reverses all autopilot actions in reverse order.
func (a *Autopilot) Rollback() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var errs []string
	for i := len(a.actions) - 1; i >= 0; i-- {
		action := a.actions[i]
		switch action.Type {
		case ActionThrottleCPU:
			quotaPath := fmt.Sprintf("/sys/fs/cgroup%s/cpu.max", action.Cgroup)
			if action.OldValue != "" {
				if err := os.WriteFile(quotaPath, []byte(action.OldValue), 0644); err != nil {
					errs = append(errs, fmt.Sprintf("rollback cpu %s: %v", action.Cgroup, err))
				} else {
					log.Printf("AUTOPILOT ROLLBACK: cpu %s → %s", action.Cgroup, action.OldValue)
				}
			}
		case ActionIsolateProc:
			if action.OldValue != "" {
				procsPath := fmt.Sprintf("/sys/fs/cgroup%s/cgroup.procs", action.OldValue)
				if err := os.WriteFile(procsPath, []byte(fmt.Sprintf("%d\n", action.PID)), 0644); err != nil {
					errs = append(errs, fmt.Sprintf("rollback isolate pid %d: %v", action.PID, err))
				} else {
					log.Printf("AUTOPILOT ROLLBACK: PID %d → %s", action.PID, action.OldValue)
				}
			}
		case ActionSetIONice:
			// Reset to best-effort class 0
			cmd := exec.Command("ionice", "-c", "2", "-n", "4", "-p", fmt.Sprintf("%d", action.PID))
			if err := cmd.Run(); err != nil {
				errs = append(errs, fmt.Sprintf("rollback ionice pid %d: %v", action.PID, err))
			}
		}
	}

	a.actions = nil

	if len(errs) > 0 {
		return fmt.Errorf("rollback errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Monitor watches system health after actions and auto-rollbacks if things get worse.
func (a *Autopilot) Monitor(ticker Ticker, timeout time.Duration) {
	if len(a.actions) == 0 {
		return
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// Get baseline health
	_, _, baseResult := ticker.Tick()
	if baseResult == nil {
		return
	}
	baseScore := baseResult.PrimaryScore

	checkInterval := time.NewTicker(5 * time.Second)
	defer checkInterval.Stop()

	for {
		select {
		case <-timer.C:
			log.Printf("AUTOPILOT: monitor timeout (%s) — rolling back", timeout)
			a.Rollback()
			return
		case <-checkInterval.C:
			_, _, result := ticker.Tick()
			if result == nil {
				continue
			}
			// If score increased (worsened), rollback
			if result.PrimaryScore > baseScore+10 {
				log.Printf("AUTOPILOT: score worsened (%d → %d) — rolling back",
					baseScore, result.PrimaryScore)
				a.Rollback()
				return
			}
			// If healthy, we're done monitoring
			if result.Health == 0 { // HealthOK
				log.Printf("AUTOPILOT: system recovered — actions kept")
				return
			}
		}
	}
}

// Actions returns a copy of all recorded actions.
func (a *Autopilot) Actions() []AutopilotAction {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AutopilotAction, len(a.actions))
	copy(out, a.actions)
	return out
}
