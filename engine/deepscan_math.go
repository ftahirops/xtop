package engine

import "math"

// Thin wrappers so the deepscan.go callers don't need to import math — keeps
// the diff minimal and lets us swap for a unit-testable mock later.
func math_fl64bits(f float64) uint64       { return math.Float64bits(f) }
func math_fl64frombits(u uint64) float64   { return math.Float64frombits(u) }
