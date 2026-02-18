package collector

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// PSICollector reads /proc/pressure/{cpu,memory,io}.
type PSICollector struct{}

func (p *PSICollector) Name() string { return "psi" }

func (p *PSICollector) Collect(snap *model.Snapshot) error {
	var firstErr error

	cpu, err := parsePSIFile("/proc/pressure/cpu")
	if err != nil {
		firstErr = err
	} else {
		snap.Global.PSI.CPU = cpu
	}

	mem, err := parsePSIFile("/proc/pressure/memory")
	if err != nil && firstErr == nil {
		firstErr = err
	} else if err == nil {
		snap.Global.PSI.Memory = mem
	}

	io, err := parsePSIFile("/proc/pressure/io")
	if err != nil && firstErr == nil {
		firstErr = err
	} else if err == nil {
		snap.Global.PSI.IO = io
	}

	return firstErr
}

// parsePSIFile reads a PSI file and returns PSIResource.
// Format: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
//         "full avg10=0.00 avg60=0.00 avg300=0.00 total=0"
func parsePSIFile(path string) (model.PSIResource, error) {
	var res model.PSIResource
	content, err := util.ReadFileString(path)
	if err != nil {
		return res, fmt.Errorf("read %s: %w", path, err)
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		psiLine, isFull, err := parsePSILine(line)
		if err != nil {
			continue
		}
		if isFull {
			res.Full = psiLine
		} else {
			res.Some = psiLine
		}
	}
	return res, nil
}

func parsePSILine(line string) (model.PSILine, bool, error) {
	var pl model.PSILine
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return pl, false, fmt.Errorf("unexpected PSI line: %s", line)
	}

	isFull := fields[0] == "full"

	for _, f := range fields[1:] {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "avg10":
			pl.Avg10 = util.ParseFloat64(parts[1])
		case "avg60":
			pl.Avg60 = util.ParseFloat64(parts[1])
		case "avg300":
			pl.Avg300 = util.ParseFloat64(parts[1])
		case "total":
			pl.Total = util.ParseUint64(parts[1])
		}
	}
	return pl, isFull, nil
}
