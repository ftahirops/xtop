//go:build !linux

package collector

// Non-Linux fallbacks — xtop is Linux-only in practice, but keeping the
// symbols resolved for "go build ./..." on macOS developer machines.

func setIOPrioIdle() error { return nil }
func setNicePolite() error { return nil }
