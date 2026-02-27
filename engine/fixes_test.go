package engine

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ---------------------------------------------------------------------------
// Fix #1: History ring buffer copy safety
//
// Latest(), Previous(), Get(), GetRate() must return copies, not pointers into
// the ring buffer.  After pushing a new snapshot the previously returned value
// must remain unchanged.
// ---------------------------------------------------------------------------

func TestHistoryLatestReturnsCopy(t *testing.T) {
	h := NewHistory(4, 3)

	snap1 := model.Snapshot{Timestamp: time.Unix(100, 0)}
	snap1.Global.CPU.NumCPUs = 4
	h.Push(snap1)

	got := h.Latest()
	if got == nil {
		t.Fatal("Latest() returned nil after Push")
	}
	if got.Global.CPU.NumCPUs != 4 {
		t.Fatalf("expected NumCPUs=4, got %d", got.Global.CPU.NumCPUs)
	}

	// Push a second snapshot with different data.
	snap2 := model.Snapshot{Timestamp: time.Unix(200, 0)}
	snap2.Global.CPU.NumCPUs = 8
	h.Push(snap2)

	// The first returned pointer must still reflect the original value.
	if got.Global.CPU.NumCPUs != 4 {
		t.Fatalf("Latest() returned a pointer into the buffer: NumCPUs changed to %d after second Push", got.Global.CPU.NumCPUs)
	}

	// Latest() now should return the second snapshot.
	got2 := h.Latest()
	if got2 == nil || got2.Global.CPU.NumCPUs != 8 {
		t.Fatalf("Latest() after second Push: expected NumCPUs=8, got %v", got2)
	}
}

func TestHistoryPreviousReturnsCopy(t *testing.T) {
	h := NewHistory(4, 3)

	snap1 := model.Snapshot{Timestamp: time.Unix(100, 0)}
	snap1.Global.Memory.Total = 1000
	h.Push(snap1)

	snap2 := model.Snapshot{Timestamp: time.Unix(200, 0)}
	snap2.Global.Memory.Total = 2000
	h.Push(snap2)

	prev := h.Previous()
	if prev == nil {
		t.Fatal("Previous() returned nil with 2 entries")
	}
	if prev.Global.Memory.Total != 1000 {
		t.Fatalf("Previous() expected MemTotal=1000, got %d", prev.Global.Memory.Total)
	}

	// Push a third snapshot that overwrites slot of snap1 (ring wraps at cap=4).
	snap3 := model.Snapshot{Timestamp: time.Unix(300, 0)}
	snap3.Global.Memory.Total = 3000
	h.Push(snap3)

	// prev must still hold the original value.
	if prev.Global.Memory.Total != 1000 {
		t.Fatalf("Previous() returned buffer pointer: MemTotal changed to %d", prev.Global.Memory.Total)
	}
}

func TestHistoryGetReturnsCopy(t *testing.T) {
	h := NewHistory(4, 3)

	for i := 0; i < 3; i++ {
		s := model.Snapshot{Timestamp: time.Unix(int64(i*100), 0)}
		s.Global.FD.Allocated = uint64(i + 1)
		h.Push(s)
	}

	// Get(0) = oldest = FD.Allocated=1
	got := h.Get(0)
	if got == nil || got.Global.FD.Allocated != 1 {
		t.Fatalf("Get(0) expected FD.Allocated=1, got %v", got)
	}

	// Overwrite by pushing more entries (wraps the buffer).
	for i := 3; i < 6; i++ {
		s := model.Snapshot{Timestamp: time.Unix(int64(i*100), 0)}
		s.Global.FD.Allocated = uint64(i + 1)
		h.Push(s)
	}

	// Original result must be untouched.
	if got.Global.FD.Allocated != 1 {
		t.Fatalf("Get() returned buffer pointer: FD.Allocated changed to %d", got.Global.FD.Allocated)
	}
}

func TestHistoryGetRateReturnsCopy(t *testing.T) {
	h := NewHistory(4, 3)

	snap1 := model.Snapshot{Timestamp: time.Unix(100, 0)}
	h.Push(snap1)
	h.PushRate(model.RateSnapshot{DeltaSec: 1.0, CPUBusyPct: 25.0})

	snap2 := model.Snapshot{Timestamp: time.Unix(200, 0)}
	h.Push(snap2)
	h.PushRate(model.RateSnapshot{DeltaSec: 1.0, CPUBusyPct: 50.0})

	// GetRate(0) = oldest = CPUBusyPct=25
	got := h.GetRate(0)
	if got == nil {
		t.Fatal("GetRate(0) returned nil")
	}
	if got.CPUBusyPct != 25.0 {
		t.Fatalf("GetRate(0) expected CPUBusyPct=25, got %f", got.CPUBusyPct)
	}

	// Overwrite by pushing more (wraps buffer).
	for i := 2; i < 6; i++ {
		s := model.Snapshot{Timestamp: time.Unix(int64(i*100), 0)}
		h.Push(s)
		h.PushRate(model.RateSnapshot{DeltaSec: 1.0, CPUBusyPct: float64(i * 100)})
	}

	// Original must be untouched.
	if got.CPUBusyPct != 25.0 {
		t.Fatalf("GetRate() returned buffer pointer: CPUBusyPct changed to %f", got.CPUBusyPct)
	}
}

func TestHistoryGetOutOfBounds(t *testing.T) {
	h := NewHistory(4, 3)

	if h.Latest() != nil {
		t.Fatal("Latest() on empty history should be nil")
	}
	if h.Previous() != nil {
		t.Fatal("Previous() on empty history should be nil")
	}
	if h.Get(-1) != nil {
		t.Fatal("Get(-1) should be nil")
	}
	if h.Get(0) != nil {
		t.Fatal("Get(0) on empty history should be nil")
	}
	if h.GetRate(0) != nil {
		t.Fatal("GetRate(0) on empty history should be nil")
	}

	h.Push(model.Snapshot{Timestamp: time.Unix(1, 0)})
	if h.Previous() != nil {
		t.Fatal("Previous() with only 1 entry should be nil")
	}
	if h.Get(1) != nil {
		t.Fatal("Get(1) with only 1 entry should be nil")
	}
}

// ---------------------------------------------------------------------------
// Fix #19: Anomaly stddev calculation
//
// The inline stddev computation in trackBiggestChange uses population stddev:
//   variance = (sumSq / n) - mean^2
//   stddev   = math.Sqrt(variance)
//
// We replicate the formula and verify with known values.
// [2, 4, 4, 4, 5, 5, 7, 9] -> mean=5, variance=4, stddev=2.0
// ---------------------------------------------------------------------------

// computePopulationStddev mirrors the inline logic from trackBiggestChange.
func computePopulationStddev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum, sumSq float64
	for _, v := range values {
		sum += v
		sumSq += v * v
	}
	n := float64(len(values))
	mean := sum / n
	variance := sumSq/n - mean*mean
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

func TestStddevKnownValues(t *testing.T) {
	// Classic textbook example: mean=5, population stddev=2.0
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	got := computePopulationStddev(values)
	if math.Abs(got-2.0) > 0.001 {
		t.Fatalf("expected stddev ~2.0, got %f", got)
	}
}

func TestStddevAllSame(t *testing.T) {
	values := []float64{5, 5, 5, 5}
	got := computePopulationStddev(values)
	if got != 0 {
		t.Fatalf("expected stddev=0 for identical values, got %f", got)
	}
}

func TestStddevSingleValue(t *testing.T) {
	values := []float64{42}
	got := computePopulationStddev(values)
	if got != 0 {
		t.Fatalf("expected stddev=0 for single value, got %f", got)
	}
}

func TestStddevEmpty(t *testing.T) {
	got := computePopulationStddev(nil)
	if got != 0 {
		t.Fatalf("expected stddev=0 for empty slice, got %f", got)
	}
}

func TestStddevTwoValues(t *testing.T) {
	// [0, 10] -> mean=5, variance=25, stddev=5
	values := []float64{0, 10}
	got := computePopulationStddev(values)
	if math.Abs(got-5.0) > 0.001 {
		t.Fatalf("expected stddev=5.0, got %f", got)
	}
}

// ---------------------------------------------------------------------------
// Fix #23: EventLogWriter rotation
//
// Write() must rotate the file when it exceeds maxSize.  After rotation the
// .1 backup file exists and the main file is small again.
// ---------------------------------------------------------------------------

func TestEventLogWriterRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")

	w := NewEventLogWriter(logPath)
	// Set a very small maxSize so rotation triggers quickly.
	w.maxSize = 100

	// Write enough events to exceed 100 bytes.
	// Each JSON-encoded Event is well over 50 bytes, so 3-4 writes should do.
	for i := 0; i < 10; i++ {
		ev := model.Event{
			ID:         "evt-" + strings.Repeat("x", 20),
			StartTime:  time.Now(),
			Bottleneck: "cpu-saturation",
			PeakScore:  80 + i,
		}
		if err := w.Write(ev); err != nil {
			t.Fatalf("Write(%d): %v", i, err)
		}
	}

	// The .1 backup file must exist after rotation.
	backupPath := logPath + ".1"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Fatalf("expected backup file %s to exist after rotation", backupPath)
	}

	// The main file should be smaller than the backup (it was just rotated).
	mainInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat main log: %v", err)
	}
	backupInfo, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}

	// The main file must be small -- it should contain only the events written
	// after the most recent rotation.
	if mainInfo.Size() > backupInfo.Size()+200 {
		t.Fatalf("main file (%d bytes) should be roughly <= backup (%d bytes) after rotation",
			mainInfo.Size(), backupInfo.Size())
	}

	// Verify we can read back events from the main file.
	events, err := ReadEventLog(logPath)
	if err != nil {
		t.Fatalf("ReadEventLog: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least 1 event in main log after rotation")
	}
}

func TestEventLogWriterNoRotationUnderSize(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")

	w := NewEventLogWriter(logPath)
	// Default maxSize is 10MB; a single event won't trigger rotation.

	ev := model.Event{ID: "evt-1", Bottleneck: "ok"}
	if err := w.Write(ev); err != nil {
		t.Fatalf("Write: %v", err)
	}

	backupPath := logPath + ".1"
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatal("backup file should not exist when file is under maxSize")
	}

	events, err := ReadEventLog(logPath)
	if err != nil {
		t.Fatalf("ReadEventLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

// ---------------------------------------------------------------------------
// Fix #38: Recorder error logging
//
// RecordTickWithProbe must not panic when the underlying writer returns an
// error.  It should log the error and continue.
// ---------------------------------------------------------------------------

// errorWriter is an io.Writer that always returns an error.
type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func TestRecorderErrorWriterDoesNotPanic(t *testing.T) {
	// We cannot easily construct an Engine without real collectors hitting
	// /proc, so instead we directly construct a Recorder with a nil-safe
	// approach: create a real engine (its Tick will fail gracefully on
	// non-Linux or missing /proc, returning a snapshot with errors).
	eng := NewEngine(10, 3)
	rec := NewRecorder(eng, errorWriter{})
	defer rec.Close()

	// This must not panic even though the writer always errors.
	// On a test machine without /proc the snapshot may have errors but
	// the recorder itself must survive the encode failure.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("RecordTickWithProbe panicked: %v", r)
			}
		}()
		rec.RecordTickWithProbe(nil)
	}()

	// Call it a few more times to ensure repeated errors don't accumulate
	// into a crash.
	for i := 0; i < 5; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RecordTickWithProbe panicked on iteration %d: %v", i, r)
				}
			}()
			rec.RecordTickWithProbe(&ProbeFindings{
				Pack:    "offcpu",
				Summary: "test probe",
			})
		}()
	}
}

func TestRecorderWithProbeFindings(t *testing.T) {
	eng := NewEngine(10, 3)
	rec := NewRecorder(eng, errorWriter{})
	defer rec.Close()

	// Should not panic with non-nil probe findings and a failing writer.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("RecordTickWithProbe with findings panicked: %v", r)
			}
		}()
		probe := &ProbeFindings{
			StartTime:  time.Now(),
			Duration:   5 * time.Second,
			Pack:       "iolatency",
			Bottleneck: "io-latency",
			ConfBoost:  15,
			Summary:    "sda p99 = 42ms",
		}
		rec.RecordTickWithProbe(probe)
	}()
}
