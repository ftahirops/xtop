package identity

import (
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// Version extraction commands: service name -> (binary, args, parse func).
type versionProbe struct {
	binary string
	args   []string
	parse  func(output string) string
	stderr bool // some tools output version to stderr
}

var versionProbes = map[string]versionProbe{
	"nginx": {
		binary: "nginx",
		args:   []string{"-v"},
		stderr: true,
		parse: func(out string) string {
			// "nginx version: nginx/1.24.0"
			if idx := strings.Index(out, "nginx/"); idx >= 0 {
				v := out[idx+6:]
				if nl := strings.IndexAny(v, " \n\r"); nl >= 0 {
					v = v[:nl]
				}
				return v
			}
			return ""
		},
	},
	"mysql": {
		binary: "mysql",
		args:   []string{"--version"},
		parse: func(out string) string {
			// "mysql  Ver 8.0.35 for Linux..."
			if idx := strings.Index(out, "Ver "); idx >= 0 {
				v := out[idx+4:]
				if sp := strings.IndexAny(v, " -"); sp >= 0 {
					v = v[:sp]
				}
				return v
			}
			return ""
		},
	},
	"postgresql": {
		binary: "psql",
		args:   []string{"--version"},
		parse: func(out string) string {
			// "psql (PostgreSQL) 16.1"
			if idx := strings.Index(out, ") "); idx >= 0 {
				v := out[idx+2:]
				v = strings.TrimSpace(v)
				if nl := strings.IndexAny(v, " \n"); nl >= 0 {
					v = v[:nl]
				}
				return v
			}
			return ""
		},
	},
	"redis": {
		binary: "redis-server",
		args:   []string{"--version"},
		parse: func(out string) string {
			// "Redis server v=7.2.3 sha=..."
			if idx := strings.Index(out, "v="); idx >= 0 {
				v := out[idx+2:]
				if sp := strings.IndexAny(v, " \n"); sp >= 0 {
					v = v[:sp]
				}
				return v
			}
			return ""
		},
	},
	"docker": {
		binary: "docker",
		args:   []string{"--version"},
		parse: func(out string) string {
			// "Docker version 24.0.7, build afdd53b"
			if idx := strings.Index(out, "version "); idx >= 0 {
				v := out[idx+8:]
				if cm := strings.Index(v, ","); cm >= 0 {
					v = v[:cm]
				}
				return strings.TrimSpace(v)
			}
			return ""
		},
	},
	"kubelet": {
		binary: "kubelet",
		args:   []string{"--version"},
		parse: func(out string) string {
			// "Kubernetes v1.28.2"
			if idx := strings.Index(out, "v"); idx >= 0 {
				v := out[idx+1:]
				if nl := strings.IndexAny(v, " \n"); nl >= 0 {
					v = v[:nl]
				}
				return v
			}
			return ""
		},
	},
	"haproxy": {
		binary: "haproxy",
		args:   []string{"-v"},
		parse: func(out string) string {
			// "HAProxy version 2.8.3 ..."
			if idx := strings.Index(out, "version "); idx >= 0 {
				v := out[idx+8:]
				if sp := strings.IndexAny(v, " \n"); sp >= 0 {
					v = v[:sp]
				}
				return v
			}
			return ""
		},
	},
	"apache": {
		binary: "apache2",
		args:   []string{"-v"},
		parse: func(out string) string {
			// "Server version: Apache/2.4.57"
			if idx := strings.Index(out, "Apache/"); idx >= 0 {
				v := out[idx+7:]
				if sp := strings.IndexAny(v, " \n"); sp >= 0 {
					v = v[:sp]
				}
				return v
			}
			return ""
		},
	},
	"mongodb": {
		binary: "mongod",
		args:   []string{"--version"},
		parse: func(out string) string {
			// "db version v7.0.2"
			if idx := strings.Index(out, "db version v"); idx >= 0 {
				v := out[idx+12:]
				if nl := strings.IndexAny(v, " \n"); nl >= 0 {
					v = v[:nl]
				}
				return v
			}
			return ""
		},
	},
}

// probeVersions extracts version strings for all detected running services.
func probeVersions(id *model.ServerIdentity) {
	for i := range id.Services {
		svc := &id.Services[i]
		if !svc.Running || svc.Version != "" {
			continue
		}
		probe, ok := versionProbes[svc.Name]
		if !ok {
			continue
		}
		path, err := exec.LookPath(probe.binary)
		if err != nil {
			continue
		}
		var output string
		if probe.stderr {
			out, err := exec.Command(path, probe.args...).CombinedOutput()
			if err != nil && len(out) == 0 {
				continue
			}
			output = string(out)
		} else {
			out, err := exec.Command(path, probe.args...).Output()
			if err != nil {
				continue
			}
			output = string(out)
		}
		if v := probe.parse(output); v != "" {
			svc.Version = v
		}
	}
}
