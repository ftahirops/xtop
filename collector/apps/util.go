package apps

// prunePIDMap deletes entries from m whose PID key is not in live.
// V can be any type (struct, map, primitive).
// Callers should pass the live-PID set collected during the current tick.
// A nil live map is treated as an empty set (all entries are removed).
func prunePIDMap[V any](m map[int]V, live map[int]bool) {
	for pid := range m {
		if !live[pid] {
			delete(m, pid)
		}
	}
}
