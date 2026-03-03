package engine

import (
	"crypto/sha256"
	"fmt"

	"github.com/ftahirops/xtop/model"
)

// ComputeFingerprint generates a 16-char hex fingerprint for an incident.
// Hash: sha256(bottleneck|pattern_name|service_name)[:16].
func ComputeFingerprint(e *model.Event, result *model.AnalysisResult) string {
	bottleneck := e.Bottleneck
	pattern := ""
	service := e.CulpritProcess

	if result != nil && result.Narrative != nil {
		pattern = result.Narrative.Pattern
	}

	// Resolve service from cgroup if available
	if e.CulpritCgroup != "" {
		if svc := resolveServiceFromCgroup(e.CulpritCgroup); svc != "" {
			service = svc
		}
	}

	input := fmt.Sprintf("%s|%s|%s", bottleneck, pattern, service)
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash[:8]) // 16 hex chars
}

// resolveServiceFromCgroup extracts a service name from a cgroup path.
func resolveServiceFromCgroup(cgPath string) string {
	// Delegate to collector's resolveService logic
	// Simple inline version for the engine package
	for i := len(cgPath) - 1; i >= 0; i-- {
		if cgPath[i] == '/' {
			leaf := cgPath[i+1:]
			if len(leaf) > 8 && leaf[len(leaf)-8:] == ".service" {
				return leaf[:len(leaf)-8]
			}
			if len(leaf) > 0 {
				return leaf
			}
		}
	}
	return cgPath
}
