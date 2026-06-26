//go:build !linux

package journal

import (
	"context"
	"time"
)

// Query is a no-op stub on non-Linux platforms.
func Query(_ context.Context, _ string, _ time.Time) ([]Entry, error) {
	return nil, nil
}
