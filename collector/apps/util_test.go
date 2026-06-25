package apps

import (
	"testing"
	"time"
)

// TestPrunePIDMap_removesDeadKeepsLive is the TDD anchor for the prunePIDMap helper.
// Write this first (will fail with "undefined: prunePIDMap"), implement util.go, then it passes.
func TestPrunePIDMap_removesDeadKeepsLive(t *testing.T) {
	t.Run("int_value_map", func(t *testing.T) {
		m := map[int]int{
			100: 1,
			200: 2,
			300: 3,
		}
		live := map[int]bool{100: true, 300: true} // PID 200 is dead
		prunePIDMap(m, live)
		if _, ok := m[200]; ok {
			t.Error("dead PID 200 should have been pruned")
		}
		if m[100] != 1 {
			t.Error("live PID 100 value should be unchanged")
		}
		if m[300] != 3 {
			t.Error("live PID 300 value should be unchanged")
		}
	})

	t.Run("struct_value_map", func(t *testing.T) {
		type prevState struct {
			val int
			at  time.Time
		}
		now := time.Now()
		m := map[int]prevState{
			1: {val: 10, at: now},
			2: {val: 20, at: now},
			3: {val: 30, at: now},
		}
		live := map[int]bool{1: true}
		prunePIDMap(m, live)
		if len(m) != 1 {
			t.Errorf("expected 1 entry after prune, got %d", len(m))
		}
		if _, ok := m[1]; !ok {
			t.Error("live PID 1 should remain")
		}
		if _, ok := m[2]; ok {
			t.Error("dead PID 2 should be pruned")
		}
		if _, ok := m[3]; ok {
			t.Error("dead PID 3 should be pruned")
		}
	})

	t.Run("empty_live_set_prunes_all", func(t *testing.T) {
		m := map[int]string{42: "foo", 99: "bar"}
		live := map[int]bool{}
		prunePIDMap(m, live)
		if len(m) != 0 {
			t.Errorf("all entries should be pruned when live is empty, got %d", len(m))
		}
	})

	t.Run("nil_live_set_treated_as_empty", func(t *testing.T) {
		m := map[int]int{1: 1}
		prunePIDMap(m, nil)
		if len(m) != 0 {
			t.Errorf("nil live set: all entries should be pruned, got %d", len(m))
		}
	})

	t.Run("empty_map_no_panic", func(t *testing.T) {
		m := map[int]int{}
		live := map[int]bool{5: true}
		prunePIDMap(m, live) // should not panic
	})
}
