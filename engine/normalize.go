package engine

// normalize returns a smooth 0..1 score for a metric value.
// Returns 0 below warn, linear ramp to 1 at crit, capped at 1.
func normalize(value, warn, crit float64) float64 {
	if crit <= warn {
		// Degenerate: treat as binary threshold at warn
		if value >= warn {
			return 1
		}
		return 0
	}
	if value <= warn {
		return 0
	}
	if value >= crit {
		return 1
	}
	return (value - warn) / (crit - warn)
}
