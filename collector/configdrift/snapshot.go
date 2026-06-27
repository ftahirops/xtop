//go:build linux

package configdrift

import (
	"errors"
	"os"
	"strings"
)

// Snapshot reads the curated Keys from the live kernel/proc filesystem and
// returns a map of Name → normalised value.
//
// Keys whose backing file does not exist or cannot be read are silently
// skipped — this is normal on VMs or kernels that lack a particular feature
// (e.g. cpufreq scaling governor). The function only returns a non-nil error
// for catastrophic failures; in practice it always returns nil.
func Snapshot() (map[string]string, error) {
	m := make(map[string]string, len(Keys))
	for _, k := range Keys {
		raw, err := os.ReadFile(k.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			// Other errors (permission denied, etc.) — skip gracefully.
			continue
		}
		val := k.Parse(strings.TrimRight(string(raw), "\n"))
		if val != "" {
			m[k.Name] = val
		}
	}
	return m, nil
}
