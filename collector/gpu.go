package collector

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// GPUCollector collects NVIDIA GPU metrics via nvidia-smi.
type GPUCollector struct{}

func (c *GPUCollector) Name() string { return "gpu" }

func (c *GPUCollector) Collect(snap *model.Snapshot) error {
	path, err := exec.LookPath("nvidia-smi")
	if err != nil || path == "" {
		return nil // No GPU, not an error
	}

	out, err := exec.Command("nvidia-smi",
		"--query-gpu=index,name,driver_version,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw,power.limit,fan.speed",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil
	}
	snap.Global.GPU.Available = true

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ", ")
		if len(fields) < 11 {
			continue
		}
		dev := model.GPUDevice{}
		dev.Index, _ = strconv.Atoi(strings.TrimSpace(fields[0]))
		dev.Name = strings.TrimSpace(fields[1])
		dev.Driver = strings.TrimSpace(fields[2])
		dev.UtilGPU, _ = strconv.ParseFloat(strings.TrimSpace(fields[3]), 64)
		dev.UtilMem, _ = strconv.ParseFloat(strings.TrimSpace(fields[4]), 64)
		memUsedMB, _ := strconv.ParseFloat(strings.TrimSpace(fields[5]), 64)
		dev.MemUsed = uint64(memUsedMB * 1024 * 1024)
		memTotalMB, _ := strconv.ParseFloat(strings.TrimSpace(fields[6]), 64)
		dev.MemTotal = uint64(memTotalMB * 1024 * 1024)
		dev.Temperature, _ = strconv.Atoi(strings.TrimSpace(fields[7]))
		dev.PowerDraw, _ = strconv.ParseFloat(strings.TrimSpace(fields[8]), 64)
		dev.PowerLimit, _ = strconv.ParseFloat(strings.TrimSpace(fields[9]), 64)
		fan := strings.TrimSpace(fields[10])
		if fan == "[N/A]" || fan == "" {
			dev.FanSpeed = -1
		} else {
			dev.FanSpeed, _ = strconv.Atoi(fan)
		}
		snap.Global.GPU.Devices = append(snap.Global.GPU.Devices, dev)
	}

	// Query GPU processes
	pout, err := exec.Command("nvidia-smi",
		"--query-compute-apps=pid,name,used_memory",
		"--format=csv,noheader,nounits").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(pout)), "\n") {
			if line == "" || strings.Contains(line, "no running") {
				continue
			}
			fields := strings.Split(line, ", ")
			if len(fields) < 3 {
				continue
			}
			proc := model.GPUProcess{}
			proc.PID, _ = strconv.Atoi(strings.TrimSpace(fields[0]))
			proc.Name = strings.TrimSpace(fields[1])
			memMB, _ := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
			proc.MemUsed = uint64(memMB * 1024 * 1024)
			if len(snap.Global.GPU.Devices) > 0 {
				snap.Global.GPU.Devices[0].Processes = append(snap.Global.GPU.Devices[0].Processes, proc)
			}
		}
	}

	return nil
}
