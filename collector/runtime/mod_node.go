package runtime

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
)

// NodeModule detects Node.js processes by comm name.
type NodeModule struct {
	detected []nodeProcess
	active   bool
	mu       sync.Mutex
}

type nodeProcess struct {
	PID  int
	Comm string
}

// NewNodeModule creates a new Node.js runtime module.
func NewNodeModule() *NodeModule {
	return &NodeModule{}
}

func (m *NodeModule) Name() string        { return "node" }
func (m *NodeModule) DisplayName() string  { return "Node.js" }

func (m *NodeModule) Detect(processes []model.ProcessMetrics) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	var found []nodeProcess
	for _, p := range processes {
		if p.Comm == "node" {
			found = append(found, nodeProcess{PID: p.PID, Comm: p.Comm})
		}
	}

	m.detected = found
	m.active = len(found) > 0
	return m.active
}

func (m *NodeModule) Collect() []model.RuntimeProcessMetrics {
	m.mu.Lock()
	procs := make([]nodeProcess, len(m.detected))
	copy(procs, m.detected)
	m.mu.Unlock()

	var result []model.RuntimeProcessMetrics
	for _, np := range procs {
		rss := readProcRSSMB(np.PID)
		threads := readProcThreads(np.PID)
		cmdline := readProcCmdline(np.PID)

		rpm := model.RuntimeProcessMetrics{
			PID:          np.PID,
			Comm:         np.Comm,
			Runtime:      "node",
			WorkingSetMB: rss,
			ThreadCount:  threads,
			Extra:        make(map[string]string),
		}

		// Parse --max-old-space-size from cmdline
		if limit := parseNodeHeapLimit(cmdline); limit > 0 {
			rpm.Extra["heap_limit_mb"] = fmt.Sprintf("%d", limit)
		}

		// Parse --inspect port
		if port := parseNodeInspectPort(cmdline); port != "" {
			rpm.Extra["inspect_port"] = port
		}

		// UV_THREADPOOL_SIZE from environ
		env := readProcEnviron(np.PID)
		if uvSize, ok := env["UV_THREADPOOL_SIZE"]; ok {
			rpm.Extra["uv_threadpool_size"] = uvSize
		}

		result = append(result, rpm)
	}
	return result
}

func (m *NodeModule) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *NodeModule) ProcessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.detected)
}

// parseNodeHeapLimit extracts --max-old-space-size=N from cmdline.
func parseNodeHeapLimit(cmdline string) int {
	args := strings.Split(cmdline, "\x00")
	for _, arg := range args {
		if strings.HasPrefix(arg, "--max-old-space-size=") {
			val := strings.TrimPrefix(arg, "--max-old-space-size=")
			return atoi(val)
		}
		if strings.HasPrefix(arg, "--max_old_space_size=") {
			val := strings.TrimPrefix(arg, "--max_old_space_size=")
			return atoi(val)
		}
	}
	return 0
}

// parseNodeInspectPort extracts --inspect[=host:port] from cmdline.
func parseNodeInspectPort(cmdline string) string {
	args := strings.Split(cmdline, "\x00")
	for _, arg := range args {
		if strings.HasPrefix(arg, "--inspect=") {
			return strings.TrimPrefix(arg, "--inspect=")
		}
		if arg == "--inspect" {
			return "9229" // default
		}
		if strings.HasPrefix(arg, "--inspect-brk=") {
			return strings.TrimPrefix(arg, "--inspect-brk=")
		}
		if arg == "--inspect-brk" {
			return "9229"
		}
	}
	return ""
}
