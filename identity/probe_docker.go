package identity

import (
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// probeDockerContainers queries docker for running containers.
func probeDockerContainers(id *model.ServerIdentity) {
	path, err := exec.LookPath("docker")
	if err != nil {
		return
	}

	out, err := exec.Command(path, "ps", "-a",
		"--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}").Output()
	if err != nil {
		return
	}

	lines := strings.TrimSpace(string(out))
	if lines == "" {
		return
	}

	for _, line := range strings.Split(lines, "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) < 4 {
			continue
		}
		c := model.DockerContainer{
			ID:     fields[0],
			Name:   fields[1],
			Image:  fields[2],
			Status: fields[3],
		}
		if len(fields) >= 5 {
			c.Ports = fields[4]
		}
		id.Containers = append(id.Containers, c)
	}
}
