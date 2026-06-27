//go:build !linux

package configdrift

// Snapshot is a no-op stub on non-Linux platforms.
func Snapshot() (map[string]string, error) {
	return map[string]string{}, nil
}
