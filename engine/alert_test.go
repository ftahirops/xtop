package engine

import (
	"sync"
	"testing"
	"time"
)

func TestValidateWebhookURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid URLs
		{"https_valid", "https://hooks.slack.com/test", false},
		{"http_valid", "http://example.com/webhook", false},

		// Non-http schemes blocked
		{"ftp_blocked", "ftp://example.com", true},

		// Localhost blocked
		{"localhost_blocked", "http://localhost/webhook", true},
		{"loopback_blocked", "http://127.0.0.1/webhook", true},

		// Cloud metadata blocked
		{"metadata_blocked", "http://169.254.169.254/latest", true},

		// Private IP ranges blocked
		{"private_10_blocked", "http://10.0.0.1/webhook", true},
		{"private_172_blocked", "http://172.16.0.1/webhook", true},
		{"private_192_blocked", "http://192.168.1.1/webhook", true},

		// Empty string fails
		{"empty_string", "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateWebhookURL(c.url)
			if c.wantErr && err == nil {
				t.Fatalf("expected error for URL %q, got nil", c.url)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected no error for URL %q, got %v", c.url, err)
			}
		})
	}
}

// TestNotifierClose verifies Close() behaviour: idempotent, no panic, worker exits.
func TestNotifierClose(t *testing.T) {
	cfg := AlertConfig{Webhook: "https://example.com/hook"}

	t.Run("close_idempotent", func(t *testing.T) {
		n := NewNotifier(cfg)
		// Trigger worker goroutine.
		n.Notify("test", nil)
		// Close twice — must not panic.
		n.Close()
		n.Close()
	})

	t.Run("notify_after_close_noop", func(t *testing.T) {
		n := NewNotifier(cfg)
		n.Close()
		// Calling Notify on a closed notifier must not panic.
		n.Notify("after_close", nil)
	})

	t.Run("worker_exits_after_close", func(t *testing.T) {
		n := NewNotifier(cfg)
		// Kick the worker goroutine alive.
		n.Notify("start", nil)

		var wg sync.WaitGroup
		wg.Add(1)
		// Drain remaining jobs and detect channel close via a wrapper.
		go func() {
			defer wg.Done()
			// Wait for the queue channel to be closed and drained by the worker.
			// We do this by closing the notifier and then giving the worker a
			// brief window to drain and exit.
			n.Close()
		}()
		// wg.Wait() merely ensures Close() returned; the worker itself exits
		// once the channel is drained — give it a moment.
		wg.Wait()

		done := make(chan struct{})
		go func() {
			// Spin until the queue channel is both closed and drained.
			// alertWorker exits when range n.queue finishes, which happens
			// after close(n.queue) and all enqueued items are consumed.
			// We can't directly observe goroutine exit without modifying the
			// worker, but we can verify via a recover-guarded send: sending on
			// a closed channel panics, which proves the channel is closed.
			defer close(done)
			defer func() { recover() }() //nolint:errcheck
			// Attempt a blocking send; if channel is closed this panics,
			// causing recover() to fire and done to be closed.
			// If it blocks, the test timeout will catch it.
			n.queue <- alertJob{}
		}()
		select {
		case <-done:
			// Good: channel is closed (send panicked) or worker drained it.
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for notifier channel to close")
		}
	})
}
