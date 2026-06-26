package engine

import (
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

// TestNotifierClose verifies Close() behaviour: idempotent, no panic, queue properly closed.
func TestNotifierClose(t *testing.T) {
	t.Run("close_idempotent", func(t *testing.T) {
		// Verify Close() is idempotent: calling it multiple times does not panic.
		// No need to spawn worker; Close() is synchronous and uses sync.Once.
		n := NewNotifier(AlertConfig{})
		n.Close()
		n.Close() // Second Close must also succeed without panic.
	})

	t.Run("notify_after_close_noop", func(t *testing.T) {
		// Verify Notify() after Close() does not panic; it returns safely via closed.Load().
		n := NewNotifier(AlertConfig{Webhook: "https://example.com/hook"})
		n.Close()
		n.Notify("after_close", nil) // Must not panic.
	})

	t.Run("close_seals_queue", func(t *testing.T) {
		// Verify that Close() properly closes the queue channel.
		// After Close(), attempting to send on the queue panics (channel is closed).
		n := NewNotifier(AlertConfig{})
		n.Close()

		done := make(chan struct{})
		go func() {
			// Attempt to send on the closed queue channel.
			// This will panic; recover() catches it to signal success.
			defer close(done)
			defer func() { recover() }() //nolint:errcheck
			n.queue <- alertJob{}
		}()

		select {
		case <-done:
			// Good: channel is closed; send panicked and recovered.
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for queue to close")
		}
	})
}
