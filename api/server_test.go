package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// stubProvider satisfies SnapshotProvider with no-op implementations.
type stubProvider struct{}

func (s *stubProvider) Latest() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	return nil, nil, nil
}
func (s *stubProvider) ImpactScores() []model.ImpactScore { return nil }

// TestServeReturnsErrServerClosedOnClose verifies that:
//  1. NewServer binds the listener synchronously (so the socket file exists before Serve runs).
//  2. Calling Close() causes Serve() to return promptly.
//  3. Serve() returns http.ErrServerClosed (the clean-shutdown sentinel), not a raw net error.
func TestServeReturnsErrServerClosedOnClose(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")

	srv, err := NewServer(sockPath, &stubProvider{}, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Listener must be bound before Serve is called — verify the socket file exists.
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket not created by NewServer: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve()
	}()

	// Give Serve a moment to enter its accept loop, then shut down.
	time.Sleep(10 * time.Millisecond)
	if err := srv.Close(); err != nil {
		t.Logf("Close returned (expected) error: %v", err)
	}

	// Serve must return within a reasonable deadline.
	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve returned %v; want http.ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close(); possible goroutine leak")
	}
}
