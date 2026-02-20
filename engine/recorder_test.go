package engine

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

func TestPlayerTickReplaysFrames(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	ts1 := time.Unix(1000, 0)
	ts2 := time.Unix(1005, 0)

	f1 := recordFrame{
		Snapshot: model.Snapshot{Timestamp: ts1},
	}
	f2 := recordFrame{
		Snapshot: model.Snapshot{Timestamp: ts2},
	}

	if err := enc.Encode(f1); err != nil {
		t.Fatalf("encode f1: %v", err)
	}
	if err := enc.Encode(f2); err != nil {
		t.Fatalf("encode f2: %v", err)
	}

	player, err := NewPlayer(bytes.NewReader(buf.Bytes()), 10)
	if err != nil {
		t.Fatalf("NewPlayer: %v", err)
	}

	s1, _, _ := player.Tick()
	if s1 == nil || !s1.Timestamp.Equal(ts1) {
		t.Fatalf("expected ts1, got %v", s1)
	}
	s2, _, _ := player.Tick()
	if s2 == nil || !s2.Timestamp.Equal(ts2) {
		t.Fatalf("expected ts2, got %v", s2)
	}

	if player.Engine.History.Len() != 2 {
		t.Fatalf("expected history len 2, got %d", player.Engine.History.Len())
	}
}
