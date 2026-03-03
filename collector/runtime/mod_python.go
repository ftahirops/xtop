package runtime

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
)

// PythonModule detects Python processes by comm name.
type PythonModule struct {
	detected []pythonProcess
	active   bool
	mu       sync.Mutex
}

type pythonProcess struct {
	PID  int
	Comm string
}

var pythonComms = map[string]bool{
	"python":  true,
	"python3": true,
	"python2": true,
}

// NewPythonModule creates a new Python runtime module.
func NewPythonModule() *PythonModule {
	return &PythonModule{}
}

func (m *PythonModule) Name() string        { return "python" }
func (m *PythonModule) DisplayName() string  { return "Python" }

func (m *PythonModule) Detect(processes []model.ProcessMetrics) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	var found []pythonProcess
	for _, p := range processes {
		if pythonComms[p.Comm] {
			found = append(found, pythonProcess{PID: p.PID, Comm: p.Comm})
		}
	}

	m.detected = found
	m.active = len(found) > 0
	return m.active
}

func (m *PythonModule) Collect() []model.RuntimeProcessMetrics {
	m.mu.Lock()
	procs := make([]pythonProcess, len(m.detected))
	copy(procs, m.detected)
	m.mu.Unlock()

	var result []model.RuntimeProcessMetrics
	for _, pp := range procs {
		rss := readProcRSSMB(pp.PID)
		threads := readProcThreads(pp.PID)
		cmdline := readProcCmdline(pp.PID)

		rpm := model.RuntimeProcessMetrics{
			PID:          pp.PID,
			Comm:         pp.Comm,
			Runtime:      "python",
			WorkingSetMB: rss,
			ThreadCount:  threads,
			Extra:        make(map[string]string),
		}

		// Framework detection from cmdline
		framework := detectPythonFramework(cmdline)
		if framework != "" {
			rpm.Extra["framework"] = framework
		}

		// Interpreter detection from /proc/PID/exe
		exe := readProcExe(pp.PID)
		interp := detectPythonInterpreter(exe)
		rpm.Extra["interpreter"] = interp

		// GIL-bound heuristic: single thread + high CPU usage
		if threads <= 1 {
			rpm.Extra["gil_bound"] = "likely"
		} else {
			rpm.Extra["gil_bound"] = "no"
		}

		result = append(result, rpm)
	}
	return result
}

func (m *PythonModule) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *PythonModule) ProcessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.detected)
}

func detectPythonFramework(cmdline string) string {
	args := strings.Split(cmdline, "\x00")
	for _, arg := range args {
		lower := strings.ToLower(arg)
		base := strings.ToLower(filepath.Base(arg))
		switch {
		case base == "gunicorn" || strings.Contains(lower, "gunicorn"):
			return "gunicorn"
		case base == "uvicorn" || strings.Contains(lower, "uvicorn"):
			return "uvicorn"
		case strings.Contains(lower, "django"):
			return "django"
		case strings.Contains(lower, "flask"):
			return "flask"
		case strings.Contains(lower, "celery"):
			return "celery"
		case strings.Contains(lower, "fastapi"):
			return "fastapi"
		}
	}
	return ""
}

func detectPythonInterpreter(exe string) string {
	if exe == "" {
		return "cpython"
	}
	base := strings.ToLower(filepath.Base(exe))
	if strings.Contains(base, "pypy") {
		return "pypy"
	}
	return fmt.Sprintf("cpython")
}
