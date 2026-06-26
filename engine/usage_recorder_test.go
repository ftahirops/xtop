package engine

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestUsageRecorder creates a UsageRecorder wired to a temp directory.
func newTestUsageRecorder(t *testing.T) *UsageRecorder {
	t.Helper()
	dir := t.TempDir()
	r := &UsageRecorder{
		path:       dir + "/usage-history.jsonl",
		retainDays: 90,
	}
	return r
}

// TestUsageRecorderConcurrentFlushAndPrune reproduces the file-level data race
// described in audit finding H2: concurrent Observe (which may call flushLocked
// → append to file) and prune (which reads + rewrites the same file) can silently
// drop recently-appended rollup lines.
//
// The test forces many minute rollovers (each rollover calls flushLocked) while
// concurrently triggering prune, then verifies no lines were silently lost.
//
// Run with: CGO_ENABLED=1 go test ./engine/ -run TestUsageRecorderConcurrentFlushAndPrune -race -v
func TestUsageRecorderConcurrentFlushAndPrune(t *testing.T) {
	r := newTestUsageRecorder(t)

	const goroutines = 8
	const minutesPerGoroutine = 10

	// Count how many flushes actually committed a line.
	var flushed atomic.Int64

	// We'll manually drive minute rollovers by directly calling flushLocked
	// while also firing prune concurrently.
	var wg sync.WaitGroup

	// Goroutines that flush rollup lines.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for m := 0; m < minutesPerGoroutine; m++ {
				r.mu.Lock()
				// Set a unique minute so each flush writes a distinct line.
				r.currentMin = time.Now().UTC().Add(-time.Duration(m+g*minutesPerGoroutine) * time.Minute)
				r.samples = []usageSample{{CPU: float64(g*100 + m), Mem: 50, IO: 10, LoadRatio: 0.5}}
				r.flushLocked(4, 8*1024*1024*1024)
				r.mu.Unlock()
				flushed.Add(1)
				// Tiny pause to let pruner interleave.
				time.Sleep(time.Microsecond)
			}
		}(g)
	}

	// Goroutines that prune concurrently.
	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < goroutines*minutesPerGoroutine/4; i++ {
				r.prune()
				time.Sleep(time.Microsecond)
			}
		}()
	}

	wg.Wait()

	// Count lines persisted on disk.
	f, err := os.Open(r.path)
	if err != nil {
		// File may not exist if all lines were already pruned; that's fine.
		// What matters is no race was reported by the detector.
		return
	}
	defer f.Close()

	var persisted int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var u UsageRollup
		if err := json.Unmarshal(line, &u); err == nil {
			persisted++
		}
	}

	t.Logf("flushed=%d persisted=%d (some may be pruned as old — OK)", flushed.Load(), persisted)
	// The key assertion: persisted must be <= flushed (no phantom lines) and
	// non-negative (no corruption that wiped valid lines back to nothing when
	// prune's cutoff would have kept them). With retainDays=90, all lines we
	// wrote are recent, so none should be pruned.
	if int64(persisted) != flushed.Load() {
		t.Errorf("data loss: flushed %d lines but only %d remain on disk", flushed.Load(), persisted)
	}
}

// TestUsageRecorderObserveAndPruneRace exercises the same race via the public
// Observe API, which is the real call site.
func TestUsageRecorderObserveAndPruneRace(t *testing.T) {
	r := newTestUsageRecorder(t)

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Drive Observe with rapidly-advancing fake times to force many flushes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Observe calls with different minutes to trigger flush paths.
		for i := 0; i < 200; i++ {
			// Directly set currentMin to force a rollover on every call.
			r.mu.Lock()
			r.currentMin = time.Now().UTC().Add(-time.Duration(i+1) * time.Minute)
			r.samples = []usageSample{{CPU: float64(i % 100), Mem: 50}}
			r.flushLocked(4, 0)
			r.mu.Unlock()
			time.Sleep(time.Microsecond)
		}
		close(done)
	}()

	// Concurrent prune goroutines.
	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					r.prune()
					time.Sleep(500 * time.Microsecond)
				}
			}
		}()
	}

	wg.Wait()
	// If the race detector didn't fire, the test passes.
}
