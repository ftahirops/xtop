package engine

import "testing"

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
